#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <vector>
#include <iomanip>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <zip.h>
#include <mutex>
#include <thread>
#include <future>
#include <queue>
#include <condition_variable>
#include <algorithm>
#include <chrono>
#include "Json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

std::mutex print_mutex;
std::mutex error_mutex;
std::mutex state_mutex;

std::atomic<int> ignored_count(0);
std::atomic<int> new_count(0);

std::vector<std::string> errors;

class ThreadPool
{
public:
    ThreadPool(size_t num_threads);
    ~ThreadPool();

    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::invoke_result<F, Args...>::type>;

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

ThreadPool::ThreadPool(size_t num_threads) : stop(false)
{
    for (size_t i = 0; i < num_threads; ++i)
    {
        workers.emplace_back([this]
            {
                for (;;)
                {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this]
                            {
                                return this->stop || !this->tasks.empty();
                            });
                        if (this->stop && this->tasks.empty())
                            return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }

                    task();
                }
            }
        );
    }
}

ThreadPool::~ThreadPool()
{
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
    }

    condition.notify_all();
    for (std::thread& worker : workers)
        worker.join();
}

template <class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> std::future<typename std::invoke_result<F, Args...>::type>
{
    using return_type = typename std::invoke_result<F, Args...>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );

    std::future<return_type> res = task->get_future();
    {
        std::unique_lock<std::mutex> lock(queue_mutex);

        if (stop)
            throw std::runtime_error("enqueue on stopped ThreadPool");

        tasks.emplace([task]() { (*task)(); });
    }

    condition.notify_one();
    return res;
}

bool extract_zip(const std::string& zipPath, const std::string& extractDir, std::vector<std::string>& errors)
{
    int err = 0;
    zip* z = zip_open(zipPath.c_str(), ZIP_RDONLY, &err);
    if (z == nullptr)
    {
        zip_error_t ziperror;
        zip_error_init_with_code(&ziperror, err);
        std::lock_guard<std::mutex> lock(error_mutex);
        errors.emplace_back("Failed to open zip file: " + std::string(zip_error_strerror(&ziperror)));
        zip_error_fini(&ziperror);
        return false;
    }

    zip_int64_t num_entries = zip_get_num_entries(z, 0);
    for (zip_uint64_t i = 0; i < static_cast<zip_uint64_t>(num_entries); ++i)
    {
        struct zip_stat st;
        zip_stat_init(&st);
        if (zip_stat_index(z, i, 0, &st) != 0)
        {
            std::lock_guard<std::mutex> lock(error_mutex);
            errors.emplace_back("Failed to get info for index " + std::to_string(i) + " in zip.");
            zip_close(z);
            return false;
        }

        std::string filePath = st.name;

        if (filePath.back() == '/')
            continue;

        fs::path fullPath = fs::path(extractDir) / filePath;
        try
        {
            fs::create_directories(fullPath.parent_path());
        }

        catch (const fs::filesystem_error& e)
        {
            std::lock_guard<std::mutex> lock(error_mutex);
            errors.emplace_back("Failed to create directories for " + fullPath.string() + ": " + e.what());
            zip_close(z);
            return false;
        }

        zip_file* zf = zip_fopen_index(z, i, 0);
        if (zf == nullptr)
        {
            std::lock_guard<std::mutex> lock(error_mutex);
            errors.emplace_back("Failed to open file " + filePath + " in zip.");
            zip_close(z);
            return false;
        }

        std::ofstream ofs(fullPath, std::ios::binary);
        if (!ofs)
        {
            std::lock_guard<std::mutex> lock(error_mutex);
            errors.emplace_back("Failed to create file " + fullPath.string());
            zip_fclose(zf);
            zip_close(z);
            return false;
        }

        const size_t buffer_size = 1 << 16;
        std::vector<char> buffer(buffer_size);
        zip_int64_t bytes_read;
        while ((bytes_read = zip_fread(zf, buffer.data(), buffer_size)) > 0)
        {
            ofs.write(buffer.data(), bytes_read);
        }

        if (bytes_read < 0)
        {
            std::lock_guard<std::mutex> lock(error_mutex);
            errors.emplace_back("Error reading file " + filePath + " from zip.");
        }

        zip_fclose(zf);
    }

    zip_close(z);
    return true;
}

std::string sha256_file(const std::string& filename, std::vector<std::string>& errors)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        std::lock_guard<std::mutex> lock(error_mutex);
        errors.emplace_back("Unable to open file for hashing: " + filename);
        return "";
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        std::lock_guard<std::mutex> lock(error_mutex);
        errors.emplace_back("Failed to create EVP_MD_CTX for hashing: " + filename);
        return "";
    }

    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    {
        std::lock_guard<std::mutex> lock(error_mutex);
        errors.emplace_back("Failed to initialize EVP digest for file: " + filename);
        EVP_MD_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> buffer(1 << 15);
    while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()))
    {
        std::streamsize readBytes = file.gcount();
        if (readBytes > 0)
            EVP_DigestUpdate(ctx, buffer.data(), readBytes);
    }

    if (file.gcount() > 0)
    {
        EVP_DigestUpdate(ctx, buffer.data(), file.gcount());
    }

    if (1 != EVP_DigestFinal_ex(ctx, hash, NULL))
    {
        std::lock_guard<std::mutex> lock(error_mutex);
        errors.emplace_back("Failed to finalize EVP digest for file: " + filename);
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    oss << std::hex;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        oss << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return oss.str();
}

int main()
{
    auto start_time = std::chrono::high_resolution_clock::now();

    std::string zipPath = "Icons.zip";
    std::string tempExtractDir = "extracted_icons";
    std::string iconsDir = "icons";
    std::string stateFile = "state.json";

    json result;
    result["success"] = false;
    result["total"] = 0;
    result["new"] = 0;
    result["ignored"] = 0;
    result["time"] = 0.0;
    result["errors"] = json::array();

    try
    {
        if (!extract_zip(zipPath, tempExtractDir, errors))
        {
            result["errors"] = errors;
            std::cout << result.dump(4) << std::endl;
            return 1;
        }

        size_t extracted_items = std::distance(fs::directory_iterator(tempExtractDir), fs::directory_iterator{});
        if (extracted_items == 1 && fs::is_directory(fs::path(tempExtractDir) / fs::directory_iterator(tempExtractDir).operator*().path().filename()))
        {
            fs::path single_dir = (*fs::directory_iterator(tempExtractDir)).path();
            tempExtractDir = single_dir.string();
        }

        json state;
        {
            std::ifstream sf(stateFile);
            if (sf)
            {
                sf >> state;
            }
            else
            {
                state = json::object();
            }
        }

        if (!fs::exists(iconsDir))
        {
            fs::create_directory(iconsDir);
        }

        std::vector<fs::path> files;
        for (auto& entry : fs::recursive_directory_iterator(tempExtractDir))
        {
            if (!entry.is_regular_file()) continue;

            std::string ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext != ".png" && ext != ".jpg" && ext != ".jpeg")
            {
                continue;
            }

            files.emplace_back(entry.path());
        }

        result["total"] = static_cast<int>(files.size());

        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
        ThreadPool pool(num_threads);

        std::vector<std::future<void>> futures;

        for (auto& filePath : files)
        {
            futures.emplace_back(pool.enqueue([&, filePath]()
                {
                    std::string filename = filePath.filename().string();
                    std::string stem = filePath.stem().string();
                    std::string ext = filePath.extension().string();

                    std::string fileHash = sha256_file(filePath.string(), errors);
                    if (fileHash.empty())
                    {
                        return;
                    }

                    bool needsUpdate = true;
                    {
                        std::lock_guard<std::mutex> lock(state_mutex);
                        if (state.contains(stem))
                        {
                            std::string oldHash = state[stem].get<std::string>();
                            if (oldHash == fileHash)
                            {
                                needsUpdate = false;
                            }
                        }
                    }

                    if (needsUpdate)
                    {
                        fs::path destPath = fs::path(iconsDir) / filename;
                        try
                        {
                            fs::copy_file(filePath, destPath, fs::copy_options::overwrite_existing);
                            {
                                std::lock_guard<std::mutex> lock(state_mutex);
                                state[stem] = fileHash;
                            }

                            new_count++;
                        }

                        catch (const fs::filesystem_error& e)
                        {
                            std::lock_guard<std::mutex> lock(error_mutex);
                            errors.emplace_back("Failed to copy file " + filename + ": " + e.what());
                        }
                    }
                    else
                    {
                        ignored_count++;
                    }
                })
            );
        }

        for (auto& fut : futures)
        {
            fut.get();
        }

        result["new"] = new_count.load();
        result["ignored"] = ignored_count.load();

        {
            std::ofstream sf(stateFile, std::ios::trunc);
            sf << state.dump(4);
        }

        fs::remove_all(tempExtractDir);
        // fs::remove(zipPath);

        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end_time - start_time;
        result["time"] = elapsed.count();

        if (!errors.empty())
        {
            result["success"] = false;
            result["errors"] = errors;
        }
        else
        {
            result["success"] = true;
        }
    }

    catch (const std::exception& e)
    {
        std::lock_guard<std::mutex> lock(error_mutex);
        errors.emplace_back("Exception occurred: " + std::string(e.what()));
        result["errors"] = errors;
    }

    std::cout << result.dump(4) << std::endl;

    return 0;
}