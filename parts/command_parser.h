#pragma once
#include <string>
namespace HolyCommand {
inline std::wstring Trim(std::wstring s) {
    const auto a = s.find_first_not_of(L" \t\r\n");
    if (a == std::wstring::npos) return {};
    return s.substr(a, s.find_last_not_of(L" \t\r\n") - a + 1);
}
// This only splits; it NEVER establishes trust or invokes a command interpreter.
inline bool Split(const std::wstring& input, std::wstring& exe, std::wstring& args) {
    exe.clear(); args.clear();
    const auto s = Trim(input);
    if (s.empty() || s.size() > 32767 || s.find(L'\0') != std::wstring::npos) return false;
    for (wchar_t c : s) if (c < 32 && c != L'\t') return false;
    size_t end = 0;
    if (s[0] == L'"') {
        end = s.find(L'"', 1);
        if (end == std::wstring::npos || end == 1 ||
            (end + 1 < s.size() && s[end + 1] != L' ' && s[end + 1] != L'\t')) return false;
        exe = s.substr(1, end - 1); ++end;
    } else {
        // Require an unambiguous .exe token boundary. A directory called
        // something.exe cannot be mistaken for the executable itself.
        std::wstring lower = s;
        for (auto& c : lower) if (c >= L'A' && c <= L'Z') c += L'a' - L'A';
        size_t match = std::wstring::npos;
        for (size_t pos = 0; (pos = lower.find(L".exe", pos)) != std::wstring::npos; pos += 4) {
            const size_t next = pos + 4;
            if (next == s.size() || s[next] == L' ' || s[next] == L'\t') { match = next; break; }
        }
        if (match != std::wstring::npos) end = match;
        else { end = s.find_first_of(L" \t"); if (end == std::wstring::npos) end = s.size(); }
        exe = s.substr(0, end);
        if (exe.find(L'"') != std::wstring::npos) return false;
    }
    args = Trim(s.substr(end));
    return !exe.empty();
}
}
