#pragma once
#include <windows.h>
#include <atomic>
#include <thread>
#include <initializer_list>
#include "frame_pacer.h"

namespace HolyFrames {
// One waiting thread, no rendering or synchronous UI calls on this thread.
// Unlike SetTimer, waitable timers are not clamped to USER_TIMER_MINIMUM (10ms).
// Only one outstanding frame message; a busy UI drops ticks instead of building
// an unbounded backlog. HWND messages also dispatch in Win32's move/size loop.
class WindowClock {
    HANDLE stop_ = nullptr, wake_ = nullptr, timer_ = nullptr;
    std::thread thread_;
    std::atomic<bool> enabled_{false}, queued_{false}, failed_{false};
    HWND window_ = nullptr;
    UINT message_ = 0;
    LARGE_INTEGER frequency_{};
    bool highResolution_ = false;
    void CloseHandles() {
        for (HANDLE h : {stop_, wake_, timer_}) if (h) CloseHandle(h);
        stop_ = wake_ = timer_ = nullptr;
    }
    void Fail() {
        failed_.store(true);
        if (!queued_.exchange(true) && !PostMessageW(window_, message_, 0, 0)) queued_.store(false);
    }
    void Run() {
        int64_t next = 0;
        const HANDLE events[] = {stop_, wake_, timer_};
        for (;;) {
            if (!enabled_.load()) {
                CancelWaitableTimer(timer_); next = 0;
                const DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                if (wait == WAIT_OBJECT_0) return;
                if (wait != WAIT_OBJECT_0 + 1) { Fail(); return; }
                continue;
            }
            LARGE_INTEGER now{}, due{};
            if (!QueryPerformanceCounter(&now)) { Fail(); return; }
            due.QuadPart = -NextWait100ns(now.QuadPart, frequency_.QuadPart, next, false);
            if (!SetWaitableTimer(timer_, &due, 0, nullptr, nullptr, FALSE)) { Fail(); return; }
            const DWORD wait = WaitForMultipleObjects(3, events, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) return;
            if (wait == WAIT_OBJECT_0 + 1) { next = 0; continue; }
            if (wait != WAIT_OBJECT_0 + 2) { Fail(); return; }
            if (enabled_.load() && !queued_.exchange(true)) {
                if (!PostMessageW(window_, message_, 0, 0)) queued_.store(false);
            }
        }
    }
public:
    WindowClock() = default;
    WindowClock(const WindowClock&) = delete;
    WindowClock& operator=(const WindowClock&) = delete;
    ~WindowClock() { Stop(); }
    bool Start(HWND window, UINT message) {
        if (thread_.joinable() || !window || !QueryPerformanceFrequency(&frequency_) || frequency_.QuadPart <= 0) return false;
        window_ = window; message_ = message; failed_.store(false); queued_.store(false); enabled_.store(false);
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        wake_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        // Flag 2: CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, Windows 10 1803+.
        // Resolve dynamically, retaining support for older Windows/SDKs.
        using CreateTimerEx = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);
        const auto create = reinterpret_cast<CreateTimerEx>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateWaitableTimerExW"));
        if (create) timer_ = create(nullptr, nullptr, 2, TIMER_MODIFY_STATE | SYNCHRONIZE);
        highResolution_ = timer_ != nullptr;
        if (!timer_) timer_ = CreateWaitableTimerW(nullptr, FALSE, nullptr);
        if (!stop_ || !wake_ || !timer_) { CloseHandles(); return false; }
        try { thread_ = std::thread([this] { Run(); }); }
        catch (...) { CloseHandles(); return false; }
        return true;
    }
    bool Healthy() const { return thread_.joinable() && !failed_.load(); }
    bool HighResolution() const { return highResolution_; }
    void Enable(bool value) {
        if (enabled_.exchange(value) != value && wake_) SetEvent(wake_);
    }
    void Acknowledge() { queued_.store(false); }
    void Stop() {
        enabled_.store(false);
        if (stop_) SetEvent(stop_);
        if (thread_.joinable()) thread_.join();
        CloseHandles(); queued_.store(false);
    }
};
}
