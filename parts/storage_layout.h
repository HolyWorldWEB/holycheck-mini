#pragma once
#include <string>
#include <map>
#include "file_policy.h"
namespace HolyStorage {
inline const wchar_t* TabName(int tab) {
    static constexpr const wchar_t* names[] = {
        L"мл сотрудник", L"сотрудник", L"вед сотрудник", L"доп программы", L"ss"
    };
    return tab >= 0 && tab < 5 ? names[tab] : nullptr;
}
inline bool MovedToSs(const std::wstring& name) {
    return name==L"FTK Imager"||name==L"KernelLiveDumpTool"||name==L"VolatilityWorkbench"||name==L"AlternateStreamView";
}
inline std::wstring Child(const std::wstring& root, const std::wstring& leaf) {
    return root.empty() ? leaf : root + (root.back() == L'\\' ? L"" : L"\\") + leaf;
}
inline std::wstring TabPath(const std::wstring& root, int tab) {
    const auto* name = TabName(tab);
    return name && !root.empty() ? Child(root, name) : L"";
}
// A ZIP's sibling extraction directory is its filename without the final
// .zip suffix. Reuse the same Windows component policy, not a lossy sanitiser.
inline std::wstring ArchiveFolderName(const std::wstring& filename) {
    if(!HolyFiles::SafeComponent(filename)||filename.size()<=4)return {};
    if(HolyFiles::Lower(filename.substr(filename.size()-4))!=L".zip")return {};
    const auto stem=filename.substr(0,filename.size()-4);
    return HolyFiles::SafeComponent(stem)?stem:L"";
}
// Legacy FLAT-layout compatibility only. New isolated folders preserve entry
// names verbatim, including readme.txt/license.txt.
// Common root-level documentation would otherwise collide across NirSoft ZIPs.
// Only these non-runtime documentation names are namespaced, never executable,
// configuration, DLL or other resource paths. Native archive subfolders stay.
inline std::wstring RelativeName(const std::wstring& item, const std::wstring& name) {
    std::wstring lower = name;
    for (auto& c : lower) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + L'a' - L'A');
    for (const auto* document : { L"readme.txt", L"readme.md", L"license.txt", L"licence.txt", L"license", L"copying" })
        if (lower == document) return item + L"-" + name;
    return name;
}
// Explicit mutable NirSoft settings, not a wildcard permission for unknown
// neighbours. The caller must also require the peer EXE in a pinned inventory,
// a regular locked file and a small size. Configuration is NOT signed code.
inline std::wstring RuntimeConfigPeer(const std::wstring& input) {
    auto lower=input; for (auto& c:lower) if (c>=L'A' && c<=L'Z') c=static_cast<wchar_t>(c+L'a'-L'A');
    const auto slash=lower.find_last_of(L"\\/");
    const auto name=lower.substr(slash==std::wstring::npos?0:slash+1);
    for (const auto* stem : { L"recentfilesview",L"regscanner",L"lastactivityview",L"executedprogramslist",
        L"browserdownloadsview",L"usbdrivelog",L"usbdeview",L"winprefetchview",L"browsinghistoryview",
        L"alternatestreamview",L"windeflogview",L"userassistview" })
        if (name==std::wstring(stem)+L".cfg") return lower.substr(0,lower.size()-4)+L".exe";
    return {};
}
inline bool MergeFile(std::map<std::wstring, std::wstring>& files, const std::wstring& key,
                      const std::wstring& hash) {
    const auto inserted = files.emplace(key, hash);
    return inserted.second || inserted.first->second == hash;
}
}
