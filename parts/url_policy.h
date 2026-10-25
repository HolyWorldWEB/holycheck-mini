#pragma once
#include <string>
#include <vector>
#include <cstddef>
#include <algorithm>
namespace HolyUrl {
inline std::wstring Lower(std::wstring s) {
    for (auto& c : s) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
    return s;
}
inline bool ApprovedHost(const std::wstring& name) {
    const auto host = Lower(name);
    static const wchar_t* allowed[] = {
        L"voidtools.com", L"www.voidtools.com", L"github.com",
        L"release-assets.githubusercontent.com", L"objects.githubusercontent.com",
        L"github-releases.githubusercontent.com", L"nirsoft.net", L"www.nirsoft.net",
        L"usbdeview.com", L"www.usbdeview.com", L"rarlab.com", L"www.rarlab.com",
        L"download.ccleaner.com", L"osforensics.com", L"www.osforensics.com"
    };
    for (const auto* entry : allowed) if (host == entry) return true;
    return false;
}
// Strict authority pre-check, followed by WinHttpCrackUrl in Windows code.
// No credentials, aliases, IP literals, non-443 ports, fragments or backslashes.
inline bool ParseAuthority(const std::wstring& url, std::wstring& host) {
    host.clear();
    if (url.size() < 9 || url.size() > 32768 || Lower(url.substr(0, 8)) != L"https://") return false;
    for (wchar_t c : url) if (c <= 32 || c == 127 || c == L'\\' || c == L'#') return false;
    const auto stop = url.find_first_of(L"/?", 8);
    auto authority = url.substr(8, stop == std::wstring::npos ? stop : stop - 8);
    if (authority.empty() || authority.find_first_of(L"@%[]") != std::wstring::npos) return false;
    const auto colon = authority.find(L':');
    if (colon != std::wstring::npos) {
        if (authority.substr(colon) != L":443") return false;
        authority.resize(colon);
    }
    host = Lower(authority);
    return ApprovedHost(host);
}
enum class QueryResult { Success, InsufficientBuffer, Failure };
template<class Query> inline bool ReadOptionUrl(Query query, std::wstring& url) {
    url.clear(); std::vector<wchar_t> data(2048, static_cast<wchar_t>(0xffff));
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        const size_t capacity = data.size() * sizeof(wchar_t);
        size_t bytes = capacity;
        const auto result = query(data.data(), bytes);
        if (result == QueryResult::Success) {
            if (!bytes || bytes > capacity || bytes % sizeof(wchar_t)) return false;
            const size_t count = bytes / sizeof(wchar_t);
            // Some string APIs report the content bytes, others include NUL.
            // Accept either convention, but require an ACTUALLY written NUL:
            // the unused buffer is nonzero, not a fabricated terminator.
            const size_t limit = std::min(data.size(), count + 1);
            size_t length = 0; while (length < limit && data[length]) ++length;
            if (!length || length == limit) return false;
            for (size_t i = length; i < count; ++i) if (data[i]) return false;
            url.assign(data.data(), length); return true;
        }
        if (result != QueryResult::InsufficientBuffer || bytes <= capacity ||
            bytes > 128 * 1024 || bytes % sizeof(wchar_t)) return false;
        data.assign(bytes / sizeof(wchar_t), static_cast<wchar_t>(0xffff));
    }
    return false;
}

}
