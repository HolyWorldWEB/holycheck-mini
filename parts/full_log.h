#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
namespace HolyLog {
inline std::wstring LineText(const std::wstring& input) {
    std::wstring out; out.reserve(input.size() < 4096 ? input.size() : 4096);
    for (size_t i=0;i<input.size();++i) {
        if (out.size() >= 4096) { out += L" [truncated]"; break; }
        const auto value=static_cast<uint32_t>(input[i]);
        if (value >= 0xd800 && value <= 0xdbff) {
            if (sizeof(wchar_t)==2 && i+1<input.size() && input[i+1]>=0xdc00 && input[i+1]<=0xdfff) {
                if (out.size()+2>4096) { out+=L" [truncated]"; break; }
                out+=input[i];out+=input[++i];continue;
            }
            out+=L'?';continue;
        }
        if ((value>=0xdc00 && value<=0xdfff) || value>0x10ffff) { out+=L'?';continue; }
        const wchar_t c=input[i];
        if (c == L'\r') out += L"\\r";
        else if (c == L'\n') out += L"\\n";
        else if (c < 32 || c == 127) out += L'?'; else out += c;
    }
    return out;
}
// One owned writer, bounded queue, no disk I/O in Submit/the UI thread.
class Async {
    std::mutex mutex_; std::condition_variable changed_; std::thread writer_;
    std::deque<std::wstring> queue_; bool stop_ = false, running_ = false;
    uint64_t sequence_ = 0, dropped_ = 0;
    std::atomic<bool> failed_{false};
public:
    using Sink = std::function<bool(const std::wstring&)>;
    ~Async() { Stop(); }
    void Start(Sink sink) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (running_) return;
        stop_ = false; failed_.store(false);
        writer_ = std::thread([this, sink = std::move(sink)] {
            try {
                for (;;) {
                    std::deque<std::wstring> batch; uint64_t lost = 0;
                    { std::unique_lock<std::mutex> lock(mutex_);
                      changed_.wait(lock, [&] { return stop_ || !queue_.empty() || dropped_; });
                      batch.swap(queue_); lost = dropped_; dropped_ = 0;
                      if (batch.empty() && !lost && stop_) break; }
                    if (lost && !sink(L"LOGGER: queue overflow; records lost=" + std::to_wstring(lost))) failed_.store(true);
                    for (const auto& line : batch) if (!sink(line)) failed_.store(true);
                }
            } catch (...) { failed_.store(true); }
        });
        running_ = true;
    }
    bool Submit(const std::wstring& line) {
        std::lock_guard<std::mutex> guard(mutex_);
        if (!running_ || stop_ || failed_.load()) return false;
        if (queue_.size() >= 4096) { ++dropped_; changed_.notify_one(); return false; }
        queue_.push_back(L"#" + std::to_wstring(++sequence_) + L" " + LineText(line));
        changed_.notify_one(); return true;
    }
    bool Failed() const { return failed_.load(); }
    void Stop() {
        { std::lock_guard<std::mutex> guard(mutex_); if (!running_) return; stop_ = true; }
        changed_.notify_one(); if (writer_.joinable()) writer_.join();
        std::lock_guard<std::mutex> guard(mutex_); running_ = false;
    }
};
}
