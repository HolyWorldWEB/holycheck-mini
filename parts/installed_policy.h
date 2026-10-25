#pragma once
#include <string>
namespace HolyInstalled {
inline std::wstring Lower(std::wstring value) {
    for (auto& c : value) if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c + L'a' - L'A');
    return value;
}
inline std::wstring Leaf(const std::wstring& path) {
    const auto p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? path : path.substr(p + 1);
}
inline std::wstring Parent(const std::wstring& path) {
    const auto p = path.find_last_of(L"\\/");
    return p == std::wstring::npos ? L"" : path.substr(0, p);
}
// Paths must already be canonical, absolute, local and locked by the caller.
// This is product/layout binding, not an authenticity or permission check.
inline bool BoundUninstaller(const std::wstring& label, const std::wstring& executable,
                             const std::wstring& installed) {
    if (installed.empty()) return false;
    const auto exe = Lower(executable), app = Lower(installed), name = Leaf(exe);
    const auto parent = Parent(exe), appParent = Parent(app);
    if (parent.empty() || appParent.empty()) return false;
    const bool ordinaryName = name == L"uninstall.exe" || name == L"uninst.exe" ||
        name == L"unins000.exe" || name == L"unins001.exe";
    if (parent == appParent && (exe == app || ordinaryName)) return true;
    if (label != L"System Informer" || name != L"systeminformer-setup.exe") return false;
    if (parent == appParent) return true;
    const auto arch = Leaf(appParent);
    return (arch == L"amd64" || arch == L"i386" || arch == L"arm64" || arch == L"x64" || arch == L"x86") &&
           Parent(appParent) == parent;
}
inline std::wstring SystemInformerInstallRoot(const std::wstring& installed) {
    auto root=Parent(installed);
    const auto arch=Lower(Leaf(root));
    if(arch==L"amd64"||arch==L"i386"||arch==L"arm64"||arch==L"x64"||arch==L"x86") root=Parent(root);
    return root;
}
// Selection only; caller must still validate ACLs, PE, registry target and links.
inline bool StandardSystemInformerLocation(const std::wstring& installed) {
    return Lower(Leaf(installed))==L"systeminformer.exe" &&
        Lower(SystemInformerInstallRoot(installed))==LR"(c:\program files\systeminformer)";
}
inline bool SystemInformerKey(const std::wstring& input) {
    const auto key = Lower(input);
    return key == L"systeminformer" || key == L"systeminformer-preview" ||
        key == L"systeminformer-canary" || key == L"systeminformer-developer";
}
inline bool FtkDisplayName(const std::wstring& input) {
    const auto name = Lower(input);
    return name == L"ftk imager" || name.rfind(L"ftk imager ", 0) == 0 ||
           name.rfind(L"exterro ftk imager", 0) == 0 || name.rfind(L"accessdata ftk imager", 0) == 0 ||
           name.rfind(L"accessdata® ftk® imager", 0) == 0;
}
}
