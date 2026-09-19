std::wstring Win32ErrorText(DWORD error) {
    if (error == 0) return L"неизвестная ошибка";
    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    DWORD len = FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring result = (len && buffer) ? std::wstring(buffer, len) : L"ошибка Windows " + std::to_wstring(error);
    if (buffer) LocalFree(buffer);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) result.pop_back();
    return result;
}

bool IsSimpleFileName(const std::wstring& name) {
    if (name.empty() || name == L"." || name == L"..") return false;
    return name.find_first_of(L"\\/:*?\"<>|") == std::wstring::npos;
}

std::wstring JoinPath(const std::wstring& dir, const std::wstring& file) {
    if (dir.empty()) return file;
    if (dir.back() == L'\\') return dir + file;
    return dir + L"\\" + file;
}

bool EnsureDirectory(const std::wstring& path) {
    if (path.empty()) return false;
    if (CreateDirectoryW(path.c_str(), nullptr)) return true;
    if (GetLastError() != ERROR_ALREADY_EXISTS) return false;
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool DirectoryExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

bool InitDownloadDirectory() {
    PWSTR localAppData = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_CREATE, nullptr, &localAppData);
    if (FAILED(hr) || !localAppData) return false;

    std::wstring base(localAppData);
    CoTaskMemFree(localAppData);

    g_appDir = JoinPath(base, L"HolyCheck");
    if (!EnsureDirectory(g_appDir)) return false;

    g_downloadDir = JoinPath(g_appDir, L"Downloads");
    g_extractDir = JoinPath(g_appDir, L"Extracted");

    if (!EnsureDirectory(g_downloadDir)) return false;
    if (!EnsureDirectory(g_extractDir)) return false;
    return true;
}

bool IsBusy(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    return g_busyItems.find(itemIndex) != g_busyItems.end();
}

bool MarkBusy(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    return g_busyItems.insert(itemIndex).second;
}

void MarkIdle(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    g_busyItems.erase(itemIndex);
}

std::wstring ItemPath(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return {};
    std::wstring file = kItems[itemIndex].file;
    if (!IsSimpleFileName(file)) return {};
    return JoinPath(g_downloadDir, file);
}

bool FileExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static std::wstring LowerAscii(std::wstring value) {
    for (wchar_t& ch : value) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return value;
}

static bool HostEqualsOrSubdomain(const std::wstring& host, const wchar_t* allowed) {
    const std::wstring a = allowed;
    if (host == a) return true;
    if (host.size() <= a.size()) return false;
    const size_t offset = host.size() - a.size();
    return host[offset - 1] == L'.' && host.compare(offset, a.size(), a) == 0;
}

bool IsApprovedDownloadHost(const std::wstring& hostInput) {
    const std::wstring host = LowerAscii(hostInput);
    static const wchar_t* allowed[] = {
        L"voidtools.com",
        L"github.com",
        L"githubusercontent.com",
        L"nirsoft.net",
        L"usbdeview.com",
        L"rarlab.com",
        L"ccleaner.com",
        L"osforensics.com"
    };
    for (const wchar_t* entry : allowed) {
        if (HostEqualsOrSubdomain(host, entry)) return true;
    }
    return false;
}
