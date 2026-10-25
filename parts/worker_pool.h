#pragma once
#include <condition_variable>
#include <atomic>
#include <deque>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>
namespace HolyWorkers {
// A fixed pool and a bounded queue; no per-click thread creation or spinning.
class Pool {
    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<std::function<void()>> queue_, interactive_;
    std::vector<std::thread> threads_;
    bool stopping_ = false;
    unsigned interactiveBurst_ = 0; // At most three foreground tasks before a waiting bulk task.
    std::atomic<size_t> outstanding_{0};
public:
    explicit Pool(size_t count = 4) {
        try {
            for (size_t i = 0; i < count; ++i) threads_.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mutex_);
                        changed_.wait(lock, [this] { return stopping_ || !queue_.empty() || !interactive_.empty(); });
                        if (queue_.empty() && interactive_.empty() && stopping_) return;
                        const bool foreground=!interactive_.empty() && (queue_.empty() || interactiveBurst_<3);
                        auto& ready = foreground ? interactive_ : queue_;
                        if(!foreground)interactiveBurst_=0;
                        else if(interactiveBurst_<3)++interactiveBurst_;
                        task = std::move(ready.front()); ready.pop_front();
                    }
                    // Callers report exceptions to UI. Never unwind a thread.
                    try { task(); } catch (...) {}
                    outstanding_.fetch_sub(1);
                }
            });
        } catch (...) { Stop(); throw; }
    }
    Pool(const Pool&) = delete;
    Pool& operator=(const Pool&) = delete;
    ~Pool() { Stop(); }
    bool Submit(std::function<void()> task, bool interactive = false) {
        { std::lock_guard<std::mutex> lock(mutex_);
          if (stopping_ || queue_.size() + interactive_.size() >= 64) return false;
          (interactive ? interactive_ : queue_).push_back(std::move(task)); ++outstanding_; }
        changed_.notify_one(); return true;
    }
    size_t Outstanding() const { return outstanding_.load(); }
    void Stop() {
        { std::lock_guard<std::mutex> lock(mutex_); stopping_ = true; }
        changed_.notify_all();
        for (auto& t : threads_) if (t.joinable()) t.join();
        threads_.clear();
    }
};
}
