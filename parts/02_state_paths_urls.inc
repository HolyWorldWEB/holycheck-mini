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
    if (name.find_first_of(L"\\/:*?\"<>|") != std::wstring::npos) return false;
    // Win32 normalizes trailing spaces/dots, so reject ambiguous names.
    if (name.back() == L' ' || name.back() == L'.') return false;

    std::wstring stem = name;
    const size_t dot = stem.find(L'.');
    if (dot != std::wstring::npos) stem.resize(dot);
    while (!stem.empty() && (stem.back() == L' ' || stem.back() == L'.')) stem.pop_back();
    for (wchar_t& ch : stem) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }

    static const wchar_t* reserved[] = {
        L"con", L"prn", L"aux", L"nul",
        L"com1", L"com2", L"com3", L"com4", L"com5", L"com6", L"com7", L"com8", L"com9",
        L"lpt1", L"lpt2", L"lpt3", L"lpt4", L"lpt5", L"lpt6", L"lpt7", L"lpt8", L"lpt9"
    };
    for (const wchar_t* value : reserved) {
        if (stem == value) return false;
    }
    return !stem.empty();
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

static void CleanupStalePartFiles(const std::wstring& directory) {
    if (directory.empty() || !DirectoryExists(directory)) return;
    const std::wstring mask = JoinPath(directory, L"*.part");
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(mask.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            const std::wstring path = JoinPath(directory, data.cFileName);
            SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);
            DeleteFileW(path.c_str());
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);
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

    static std::atomic<bool> cleaned{false};
    bool expected = false;
    if (cleaned.compare_exchange_strong(expected, true))
        CleanupStalePartFiles(g_downloadDir);
    return true;
}

bool IsBusy(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    return g_busyItems.find(itemIndex) != g_busyItems.end();
}

bool MarkBusy(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    if (g_deleteAllBusy.load()) return false;
    return g_busyItems.insert(itemIndex).second;
}

bool TryBeginDeleteAll() {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    if (g_deleteAllBusy.load() || !g_busyItems.empty()) return false;
    g_deleteAllBusy.store(true);
    return true;
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
