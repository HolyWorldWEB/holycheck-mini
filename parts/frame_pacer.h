#pragma once
#include <algorithm>
#include <cstdint>
#include <cmath>
namespace HolyFrames {
inline unsigned NextDelay(int64_t now, int64_t frequency, int64_t& next, bool reset) {
    if (frequency <= 0) return 17;
    const int64_t period = std::max<int64_t>(1,frequency/60);
    if (reset || !next || (now > next && now-next > period*4)) next=now;
    if (next<=now) next+=((now-next)/period+1)*period;
    const int64_t remaining=next-now;
    return static_cast<unsigned>(std::clamp<int64_t>((remaining*1000+frequency-1)/frequency,1,17));
}
// Relative waitable-timer due time, in 100ns units. Keep fractional milliseconds
// instead of rounding to a WM_TIMER interval. Skip late frames, never catch up
// in a spin loop; next is a QPC deadline independent of paint duration.
inline int64_t NextWait100ns(int64_t now, int64_t frequency, int64_t& next, bool reset) {
    NextDelay(now, frequency, next, reset);
    if (frequency <= 0) return 170000;
    const long double units = std::ceil(static_cast<long double>(next-now) * 10000000.0L / frequency);
    return static_cast<int64_t>(std::clamp<long double>(units, 1, 170000));
}
}
