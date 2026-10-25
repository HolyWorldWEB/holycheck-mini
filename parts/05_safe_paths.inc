// Pin every directory component while accessing files by path. Reject aliases,
// devices, UNC, alternate streams and reparse points; never follow a junction.
struct HandleSet {
    std::vector<HANDLE> handles;
    ~HandleSet() { for (HANDLE h : handles) if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleSet() = default;
    HandleSet(const HandleSet&) = delete;
    HandleSet& operator=(const HandleSet&) = delete;
    bool Add(HANDLE h) {
        if (!h || h == INVALID_HANDLE_VALUE) return false;
        try { handles.push_back(h); }
        catch (...) { CloseHandle(h); throw; }
        return true;
    }
};

static bool LockDirectoryChain(const std::wstring& path, HandleSet& locks, bool create = false) {
    if (path.size() < 3 || path[1] != L':' || path[2] != L'\\' ||
        !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')))
        { SetLastError(ERROR_INVALID_NAME); return false; }
    size_t end = 3;
    for (;;) {
        if (end > 3) {
            const size_t start = path.find_last_of(L'\\', end - 1) + 1;
            if (!IsSimpleFileName(path.substr(start, end - start))) { SetLastError(ERROR_INVALID_NAME); return false; }
        }
        const std::wstring component = path.substr(0, end);
        if (create && end > 3 && !EnsureDirectory(component)) return false;
        HANDLE h = CreateFileW(component.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (!locks.Add(h)) return false;
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(h, &info)) return false;
        // A policy rejection must not inherit a stale FILE_NOT_FOUND error:
        // selective cleanup distinguishes absence from unsafe/unreadable paths.
        if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { SetLastError(ERROR_ACCESS_DENIED); return false; }
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) { SetLastError(ERROR_DIRECTORY); return false; }
        if (end == path.size()) return true;
        const size_t next = path.find(L'\\', end == 3 ? 3 : end + 1);
        end = next == std::wstring::npos ? path.size() : next;
        if (end == 3) { SetLastError(ERROR_INVALID_NAME); return false; }
    }
}

static bool LockRegularFile(const std::wstring& path, HandleSet& locks) {
    const size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos || !IsSimpleFileName(path.substr(slash + 1)) ||
        !LockDirectoryChain(path.substr(0, slash), locks)) return false;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                          OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (!locks.Add(h)) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    return GetFileInformationByHandle(h, &info) &&
           !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

static bool IsOwnHolyCheckDirectory(const std::wstring& path) {
    if (path.empty()) return false;

    PWSTR localAppData = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &localAppData);
    if (FAILED(hr) || !localAppData) return false;

    const std::wstring expected = JoinPath(localAppData, L"HolyCheck");
    CoTaskMemFree(localAppData);
    return _wcsicmp(path.c_str(), expected.c_str()) == 0;
}

// Delete an exact already-open file, never a pathname tree. Capture file ID at
// CREATE_NEW so rollback cannot unlink a replacement with the same name.
struct CreatedFileIdentity {
    std::wstring path; BY_HANDLE_FILE_INFORMATION identity{}; bool valid=false;
    bool Capture(const std::wstring& name,HANDLE file) {
        path=name;valid=GetFileInformationByHandle(file,&identity) && identity.nNumberOfLinks==1 &&
            !(identity.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT));return valid;
    }
    bool Remove(const std::wstring& root) const {
        if(!valid||!HolyFiles::StrictChild(path,root))return false;
        HandleSet parents,files;
        if(!LockDirectoryChain(HolyInstalled::Parent(path),parents))return false;
        HANDLE h=CreateFileW(path.c_str(),DELETE|FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if(!files.Add(h))return false;
        BY_HANDLE_FILE_INFORMATION actual{};
        if(!GetFileInformationByHandle(h,&actual)||actual.nNumberOfLinks!=1||
            (actual.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||
            actual.dwVolumeSerialNumber!=identity.dwVolumeSerialNumber||actual.nFileIndexHigh!=identity.nFileIndexHigh||actual.nFileIndexLow!=identity.nFileIndexLow)return false;
        FILE_DISPOSITION_INFO disposition{TRUE};return SetFileInformationByHandle(h,FileDispositionInfo,&disposition,sizeof(disposition))!=FALSE;
    }
};

static bool EnsureTabDirectories() {
    HandleSet directoryLocks;
    for (int tab = 0; tab < TAB_COUNT; ++tab)
        if (!LockDirectoryChain(HolyStorage::TabPath(g_appDir, tab), directoryLocks, true)) return false;
    return true;
}
static void CleanupTabPartFiles() {
    // No wildcard deletion: a foreign .part is not evidence of HolyCheck ownership.
    // Current-operation partial files are removed by captured file identity.
}
bool InitDownloadDirectory() {
    PWSTR downloads = nullptr;
    const HRESULT hr = SHGetKnownFolderPath(FOLDERID_Downloads, KF_FLAG_CREATE, nullptr, &downloads);
    if (FAILED(hr) || !downloads) return false;
    const std::wstring base(downloads); CoTaskMemFree(downloads);
    if (g_appDir.empty()) g_appDir = JoinPath(base, L"HolyCheck");
    if (!EnsureTabDirectories()) return false;
    static std::atomic<bool> cleaned{false}; bool expected = false;
    if (cleaned.compare_exchange_strong(expected, true)) CleanupTabPartFiles();
    return true;
}

// Session journal is outside HolyCheck, so Delete All does not erase evidence.
struct FullLogSession {
    HANDLE file = INVALID_HANDLE_VALUE;
    HandleSet parents;
    DWORD Start() {
        PWSTR downloads = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_Downloads, KF_FLAG_CREATE, nullptr, &downloads)) || !downloads)
            return ERROR_PATH_NOT_FOUND;
        const std::wstring base(downloads); CoTaskMemFree(downloads);
        if (!LockDirectoryChain(base, parents)) return GetLastError() ? GetLastError() : ERROR_ACCESS_DENIED;
        const auto path = JoinPath(base,L"holycheckfull.txt");
        file = CreateFileW(path.c_str(), GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (file == INVALID_HANDLE_VALUE) return GetLastError();
        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file,&info) || info.nNumberOfLinks != 1 ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            CloseHandle(file); file=INVALID_HANDLE_VALUE; return ERROR_ACCESS_DENIED;
        }
        LARGE_INTEGER end{};
        if (!SetFilePointerEx(file,end,nullptr,FILE_END)) return GetLastError();
        try { g_fullLog.Start([this](const std::wstring& line) {
            const auto value = line + L"\r\n";
            const int bytes = WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
            if (bytes <= 0) { g_fullLogError.store(ERROR_NO_UNICODE_TRANSLATION); return false; }
            std::string utf8(static_cast<size_t>(bytes),'\0');
            if (!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),&utf8[0],bytes,nullptr,nullptr)) { g_fullLogError.store(ERROR_NO_UNICODE_TRANSLATION); return false; }
            DWORD written=0;
            if (!WriteFile(file,utf8.data(),static_cast<DWORD>(utf8.size()),&written,nullptr) || written != utf8.size()) {
                g_fullLogError.store(GetLastError() ? GetLastError() : ERROR_WRITE_FAULT); return false;
            }
            // Flush on the writer, never on UI. Frequency is event-based, not per frame.
            if (!FlushFileBuffers(file)) { g_fullLogError.store(GetLastError()); return false; }
            return true;
        }); } catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
        FullLog(L"SESSION START build=release-pages-v20 pointerBits=" + std::to_wstring(sizeof(void*)*8) +
            L" pid=" + std::to_wstring(GetCurrentProcessId()));
        return ERROR_SUCCESS;
    }
    ~FullLogSession() {
        FullLog(L"SESSION END"); g_fullLog.Stop();
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    }
};
