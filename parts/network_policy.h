#pragma once
#include <algorithm>
#include <cstdint>
#include <string>
namespace HolyNet {
constexpr unsigned kMaxAttempts=3;
constexpr unsigned kMaxRetryWaitMs=120000;
inline bool RetryStatus(unsigned status) {
    return status==408||status==429||status==500||status==502||status==503||status==504;
}
struct RetryState {bool retryable=false;unsigned delayMs=0;};
enum class SecondsResult {Invalid,Ready,TooLong};
inline SecondsResult RetrySeconds(const std::wstring& value,unsigned& milliseconds) {
    milliseconds=0;
    if(value.empty())return SecondsResult::Invalid;
    // Validate ALL characters before treating a huge decimal as a long delay.
    for(auto c:value)if(c<L'0'||c>L'9')return SecondsResult::Invalid;
    unsigned seconds=0;
    for(auto c:value) {
        if(seconds>120)return SecondsResult::TooLong;
        seconds=seconds*10+static_cast<unsigned>(c-L'0');
    }
    if(seconds>120)return SecondsResult::TooLong;
    milliseconds=seconds*1000;return SecondsResult::Ready;
}
// Same bounded retry driver is used in production and mock-transport tests.
// Every attempt is a new full GET, never concatenated with a previous payload.
template<class Attempt,class Clock,class Wait,class Stopped>
bool Run(Attempt attempt,Clock now,Wait wait,Stopped stopped,std::uint64_t deadline) {
    for(unsigned n=0;n<kMaxAttempts;++n) {
        if(stopped()||now()>=deadline)return false;
        RetryState state;
        if(attempt(n,state))return true;
        if(!state.retryable||n+1==kMaxAttempts||stopped())return false;
        const unsigned delay=std::max(1000u<<n,state.delayMs);
        const auto time=now();
        if(delay>kMaxRetryWaitMs||time>=deadline||delay>=deadline-time)return false;
        if(!wait(delay))return false;
    }
    return false;
}
}
