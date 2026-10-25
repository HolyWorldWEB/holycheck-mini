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
    return HolyFiles::SafeComponent(name);
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
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

bool DirectoryExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}


bool InitDownloadDirectory();

bool IsBusy(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    return g_busyItems.find(itemIndex) != g_busyItems.end();
}

bool MarkBusy(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    if (g_cancelRequested.load() || g_deleteAllBusy.load()) return false;
    return g_busyItems.insert(itemIndex).second;
}

bool TryBeginDeleteAll() {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    if (g_cancelRequested.load() || g_deleteAllBusy.load() || !g_busyItems.empty()) return false;
    g_deleteAllBusy.store(true);
    return true;
}

void MarkIdle(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_busyMutex);
    g_busyItems.erase(itemIndex);
}

static std::wstring ItemDirectory(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return {};
    return HolyStorage::TabPath(g_appDir, kItems[itemIndex].tab);
}

std::wstring ItemPath(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return {};
    std::wstring file = kItems[itemIndex].file;
    if (!IsSimpleFileName(file)) return {};
    return JoinPath(ItemDirectory(itemIndex), file);
}

bool FileExists(const std::wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
}

static std::wstring LowerAscii(std::wstring value) {
    for (wchar_t& ch : value) {
        if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    }
    return value;
}

bool IsApprovedDownloadHost(const std::wstring& hostInput) {
    return HolyUrl::ApprovedHost(hostInput);
}
