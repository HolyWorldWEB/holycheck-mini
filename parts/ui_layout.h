#pragma once
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <deque>
namespace HolyUi {
// A failed external uninstall must not be reported as success just because
// its downloaded installer was removed (or the other way around).
inline bool DeletionSucceeded(bool installed, bool uninstalled, bool localPresent, bool localComplete) {
    return (installed || localPresent) && (!installed || uninstalled) && (!localPresent || localComplete);
}
struct Box { int x, y, w, h; };
// A mouse click must not draw a lingering focus frame. Keyboard navigation
// retains a visible solid cue unless Windows explicitly hides focus cues.
inline bool KeyboardFocusVisible(bool focused,bool disabled,bool keyboard,bool hidden) {
    return focused&&!disabled&&keyboard&&!hidden;
}
constexpr std::size_t kLogVisibleRows=8;
constexpr float kLogRowHeight=16.5f; // 15px * 1.1
constexpr int kLogIconSize=12;
constexpr int kSectionSeparatorY=166;
constexpr int kTileStartY=184; // A clear 18px gap below the separator.
struct DownloadLogLine {
    std::wstring text;
    int itemIndex=-1;
    bool folderIcon=false;
    bool downloading=false; // Transient UI status; never infer it from text.
};
inline Box LogPanel(int width,int height) {
    return {28,std::max(380,height-252),std::max(0,std::min(438,width-56)),180}; // 150px * 1.2
}
inline bool Contains(const Box& b,int x,int y) {
    return b.w>0&&b.h>0&&x>=b.x&&y>=b.y&&x-b.x<b.w&&y-b.y<b.h;
}
struct LogRange {std::size_t first,last;};
struct LogViewport {
    std::size_t fromEnd=0;
    int wheelRemainder=0;
    static std::size_t Maximum(std::size_t count) {return count>kLogVisibleRows?count-kLogVisibleRows:0;}
    void Appended(std::size_t count) {
        // Follow live output only at the bottom. Otherwise retain the user's
        // current rows, including when the bounded deque evicts its oldest row.
        const auto maximum=Maximum(count);
        if(fromEnd)fromEnd=fromEnd<maximum?fromEnd+1:maximum;
    }
    LogRange Range(std::size_t count) const {
        const auto last=count-std::min(fromEnd,Maximum(count));
        return {last-std::min(last,kLogVisibleRows),last};
    }
    bool Wheel(int delta,unsigned lines,std::size_t count) {
        const auto maximum=Maximum(count);
        fromEnd=std::min(fromEnd,maximum);
        if(!lines){wheelRemainder=0;return false;}
        const std::int64_t total=static_cast<std::int64_t>(wheelRemainder)+delta;
        const std::int64_t steps=total/120;
        wheelRemainder=static_cast<int>(total%120);
        const auto old=fromEnd;
        // UINT_MAX denotes WHEEL_PAGESCROLL. Clamp other settings before
        // multiplying, so a malformed/unusually large system value is safe.
        const auto perStep=lines==static_cast<unsigned>(-1)?kLogVisibleRows:
            std::min<std::size_t>(lines,maximum);
        const auto distance=static_cast<std::uint64_t>(steps<0?-steps:steps)*perStep;
        if(steps>0)fromEnd+=static_cast<std::size_t>(std::min<std::uint64_t>(distance,maximum-fromEnd));
        else if(steps<0)fromEnd-=static_cast<std::size_t>(std::min<std::uint64_t>(distance,fromEnd));
        return fromEnd!=old;
    }
};
// Remove only transient download statuses, retaining completed history. Keep
// the first surviving visible row anchored when viewing older messages.
inline std::size_t RemoveDownloadRows(std::deque<DownloadLogLine>& rows,LogViewport& view,int itemIndex) {
    const auto before=view.Range(rows.size());
    const bool anchored=view.fromEnd!=0;
    std::size_t index=0,removedBefore=0,removed=0;
    for(auto it=rows.begin();it!=rows.end();) {
        const bool drop=it->downloading&&(itemIndex<0||it->itemIndex==itemIndex);
        if(drop){if(index<before.first)++removedBefore;it=rows.erase(it);++removed;}
        else ++it;
        ++index;
    }
    if(removed) {
        const auto maximum=LogViewport::Maximum(rows.size());
        const auto first=std::min(before.first-removedBefore,maximum);
        view.fromEnd=anchored?maximum-first:0;
    }
    return removed;
}
inline bool AllowedWebsite(const std::wstring& url) {
    return url==L"https://detect.ac/tools"||url==L"https://ericzimmerman.github.io/#forensic-tools"||
        url==L"https://github.com/Orbdiff/PrefetchView/releases/tag/v1.5.3"||
        url==L"https://github.com/ItzIceHere/RedLotusAltChecker/releases/latest";
}
inline Box TabButton(int width,int tab) {
    if(tab<0||tab>=5)return {0,0,0,0};
    const int x=520,gap=8,last=48;
    const int ordinary=std::max(1,std::min(124,(width-x-28-last-gap*4)/4));
    return {x+tab*(ordinary+gap),74,tab==4?last:ordinary,28};
}
inline int TileColumns(int available,bool ss) {
    if(ss)return 3; // Requested fixed three-column ss grid.
    return std::max(3,std::min(6,(available+14)/164));
}
struct Footer { Box progress, cancel, status; };
inline Footer FooterLayout(int width, int height) {
    const int left = 28, gap = 16, cw = 111, ch = 29; // rounded 79x21 * 1.4
    const int cx = std::max(left, width - left - cw), cy = std::max(0, height - 16 - ch);
    return {{left, cy + (ch - 16) / 2, std::max(0, cx - gap - left), 16},
            {cx, cy, cw, ch}, {left, std::max(0, cy - 27), std::max(0, width - 56), 20}};
}
}
