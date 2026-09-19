static bool EndsWithI(const std::wstring& value, const wchar_t* suffix) {
    if (!suffix) return false;
    std::wstring a = LowerAscii(value);
    std::wstring b = LowerAscii(suffix);
    return a.size() >= b.size() && a.compare(a.size() - b.size(), b.size(), b) == 0;
}

static std::wstring ItemExtractDirectory(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return {};
    std::wstring folder = kItems[itemIndex].name;
    if (!IsSimpleFileName(folder)) return {};
    return JoinPath(g_extractDir, folder);
}

static bool IsProcessStillRunning(HANDLE process) {
    return process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
}

static void CleanupExitedTrackedProcesses() {
    std::lock_guard<std::mutex> lock(g_processMutex);
    for (size_t i = 0; i < g_launchedProcesses.size();) {
        if (!IsProcessStillRunning(g_launchedProcesses[i].process)) {
            if (g_launchedProcesses[i].process) CloseHandle(g_launchedProcesses[i].process);
            g_launchedProcesses.erase(g_launchedProcesses.begin() + i);
        } else {
            ++i;
        }
    }
}

struct ActivateWindowContext {
    DWORD pid = 0;
    HWND found = nullptr;
};

static BOOL CALLBACK FindProcessWindowProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<ActivateWindowContext*>(lParam);
    if (!ctx || ctx->found) return FALSE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != ctx->pid || !IsWindowVisible(hwnd)) return TRUE;

    ctx->found = hwnd;
    return FALSE;
}

static void BringTrackedProcessToFront(DWORD pid) {
    if (!pid) return;
    ActivateWindowContext ctx{};
    ctx.pid = pid;
    EnumWindows(FindProcessWindowProc, reinterpret_cast<LPARAM>(&ctx));
    if (!ctx.found) return;

    if (IsIconic(ctx.found)) ShowWindowAsync(ctx.found, SW_RESTORE);
    SetForegroundWindow(ctx.found);
}

static bool ActivateAlreadyRunningItem(int itemIndex) {
    CleanupExitedTrackedProcesses();

    DWORD pid = 0;
    {
        std::lock_guard<std::mutex> lock(g_processMutex);
        for (const auto& entry : g_launchedProcesses) {
            if (entry.itemIndex == itemIndex && IsProcessStillRunning(entry.process)) {
                pid = entry.pid;
                break;
            }
        }
    }

    if (!pid) return false;
    BringTrackedProcessToFront(pid);
    return true;
}

static void TrackLaunchedProcess(int itemIndex, HANDLE process) {
    if (!process) return;
    const DWORD pid = GetProcessId(process);
    if (!pid) {
        CloseHandle(process);
        return;
    }

    std::lock_guard<std::mutex> lock(g_processMutex);
    g_launchedProcesses.push_back({ itemIndex, process, pid });
}

static bool IsRegistryExplorerItemIndex(int itemIndex) {
    return itemIndex >= 0 &&
           static_cast<size_t>(itemIndex) < kItemCount &&
           _wcsicmp(kItems[itemIndex].name, L"RegistryExplorer") == 0;
}

static bool IsPathUnderDirectory(const std::wstring& path, const std::wstring& base);
static bool VerifyCachedExtractedPathForOpen(int itemIndex, const std::wstring& path,
                                             std::wstring& error);

static bool OpenTrackedPath(int itemIndex, const std::wstring& path, std::wstring& error) {
    if (path.empty() || !FileExists(path)) {
        error = L"Файл для запуска не найден.";
        return false;
    }

    // Не создаём второй экземпляр по повторному клику, пока ранее открытый
    // процесс этой же программы ещё работает.
    if (ActivateAlreadyRunningItem(itemIndex)) return true;

    // Keep a read handle without write/delete sharing until ShellExecuteExW
    // has opened the target. This narrows the check-to-launch race: another
    // same-user process cannot replace the file between verification and launch.
    HANDLE launchLock = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (launchLock == INVALID_HANDLE_VALUE) {
        error = L"Не удалось заблокировать файл на время запуска: " +
                Win32ErrorText(GetLastError());
        return false;
    }

    // Verify while the no-write/no-delete-sharing lock is held. This closes
    // the remaining local replacement window between the earlier check and
    // ShellExecuteExW.
    const std::wstring downloadedPath = ItemPath(itemIndex);
    const std::wstring extractedRoot = ItemExtractDirectory(itemIndex);
    bool integrityOk = true;
    if (!downloadedPath.empty() && _wcsicmp(downloadedPath.c_str(), path.c_str()) == 0) {
        integrityOk = VerifyPinnedPayloadForItem(itemIndex, path, error);
    } else if (!extractedRoot.empty() && IsPathUnderDirectory(path, extractedRoot)) {
        integrityOk = VerifyCachedExtractedPathForOpen(itemIndex, path, error);
    }
    if (!integrityOk) {
        CloseHandle(launchLock);
        return false;
    }

    // Registry Explorer для полноценного доступа к системным веткам реестра
    // запускается через штатный Windows UAC. Никакого обхода UAC нет: пользователь
    // видит обычное системное окно подтверждения. Остальные программы запускаются
    // с обычными правами.
    const bool elevate = IsRegistryExplorerItemIndex(itemIndex);

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.hwnd = g_mainWindow;
    sei.lpVerb = elevate ? L"runas" : L"open";
    sei.lpFile = path.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        const DWORD code = GetLastError();
        CloseHandle(launchLock);
        if (elevate && code == ERROR_CANCELLED)
            error = L"Запуск Registry Explorer от имени администратора отменён.";
        else
            error = L"Windows не смогла открыть программу: " + Win32ErrorText(code);
        return false;
    }

    CloseHandle(launchLock);
    if (sei.hProcess) TrackLaunchedProcess(itemIndex, sei.hProcess);
    return true;
}

struct CloseWindowsContext {
    std::set<DWORD> pids;
};

static BOOL CALLBACK CloseTrackedWindowProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<CloseWindowsContext*>(lParam);
    if (!ctx) return TRUE;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (ctx->pids.find(pid) != ctx->pids.end()) {
        // Только штатное закрытие окна. TerminateProcess намеренно не используется.
        PostMessageW(hwnd, WM_CLOSE, 0, 0);
    }
    return TRUE;
}

static void CloseTrackedProgramsGracefully() {
    CleanupExitedTrackedProcesses();

    CloseWindowsContext ctx;
    {
        std::lock_guard<std::mutex> lock(g_processMutex);
        for (const auto& entry : g_launchedProcesses) {
            if (IsProcessStillRunning(entry.process)) ctx.pids.insert(entry.pid);
        }
    }

    if (ctx.pids.empty()) return;
    EnumWindows(CloseTrackedWindowProc, reinterpret_cast<LPARAM>(&ctx));

    const ULONGLONG deadline = GetTickCount64() + 2500ULL;
    for (;;) {
        CleanupExitedTrackedProcesses();
        bool anyRunning = false;
        {
            std::lock_guard<std::mutex> lock(g_processMutex);
            for (const auto& entry : g_launchedProcesses) {
                if (IsProcessStillRunning(entry.process)) {
                    anyRunning = true;
                    break;
                }
            }
        }
        if (!anyRunning || GetTickCount64() >= deadline) break;
        Sleep(50);
    }
}

static void ReleaseTrackedProcessHandles() {
    std::lock_guard<std::mutex> lock(g_processMutex);
    for (auto& entry : g_launchedProcesses) {
        if (entry.process) CloseHandle(entry.process);
        entry.process = nullptr;
    }
    g_launchedProcesses.clear();
}



// -----------------------------------------------------------------------------
// System Informer integration.
static std::wstring FileNameOnly(const std::wstring& path);
// Only documented Windows registry locations are inspected. No process-name
// scanning, hidden shells or GUI automation are used.
// -----------------------------------------------------------------------------
static bool IsSystemInformerItemIndex(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    return LowerAscii(kItems[itemIndex].name) == L"systeminformer";
}

static std::wstring TrimWhitespace(std::wstring value) {
    size_t first = value.find_first_not_of(L" \t\r\n");
    if (first == std::wstring::npos) return {};
    size_t last = value.find_last_not_of(L" \t\r\n");
    return value.substr(first, last - first + 1);
}

static bool ReadRegistryStringValue(HKEY key, const wchar_t* valueName, std::wstring& out) {
    out.clear();
    DWORD type = 0;
    DWORD bytes = 0;
    LONG status = RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || bytes == 0 || (type != REG_SZ && type != REG_EXPAND_SZ)) return false;

    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 2, L'\0');
    status = RegQueryValueExW(key, valueName, nullptr, &type,
                              reinterpret_cast<LPBYTE>(buffer.data()), &bytes);
    if (status != ERROR_SUCCESS) return false;

    out.assign(buffer.data());
    out = TrimWhitespace(out);
    if (type == REG_EXPAND_SZ && !out.empty()) {
        DWORD needed = ExpandEnvironmentStringsW(out.c_str(), nullptr, 0);
        if (needed > 1) {
            std::vector<wchar_t> expanded(needed + 1, L'\0');
            if (ExpandEnvironmentStringsW(out.c_str(), expanded.data(), needed) != 0)
                out.assign(expanded.data());
        }
    }
    return !out.empty();
}

static bool ReadRegistryDwordValue(HKEY key, const wchar_t* valueName, DWORD& out) {
    out = 0;
    DWORD type = 0;
    DWORD bytes = sizeof(out);
    LONG status = RegQueryValueExW(key, valueName, nullptr, &type,
                                   reinterpret_cast<LPBYTE>(&out), &bytes);
    return status == ERROR_SUCCESS && type == REG_DWORD && bytes == sizeof(out);
}

static bool LooksLikeMsiProductCode(const std::wstring& text) {
    if (text.size() != 38 || text.front() != L'{' || text.back() != L'}') return false;
    for (size_t i = 1; i + 1 < text.size(); ++i) {
        if (i == 9 || i == 14 || i == 19 || i == 24) {
            if (text[i] != L'-') return false;
            continue;
        }
        const wchar_t ch = text[i];
        const bool hex = (ch >= L'0' && ch <= L'9') ||
                         (ch >= L'a' && ch <= L'f') ||
                         (ch >= L'A' && ch <= L'F');
        if (!hex) return false;
    }
    return true;
}

static std::wstring RegistryPathToExecutable(std::wstring raw) {
    raw = TrimWhitespace(raw);
    if (raw.empty()) return {};

    std::wstring path;
    if (raw.front() == L'"') {
        size_t end = raw.find(L'"', 1);
        path = end == std::wstring::npos ? raw.substr(1) : raw.substr(1, end - 1);
    } else {
        // DisplayIcon often uses C:\\path\\app.exe,0.
        size_t comma = raw.find(L',');
        path = raw.substr(0, comma);
    }
    return TrimWhitespace(path);
}

static bool LooksLikeSystemInformerExecutable(const std::wstring& path) {
    if (path.empty() || !EndsWithI(path, L".exe")) return false;
    const std::wstring lower = LowerAscii(FileNameOnly(path));
    return lower == L"systeminformer.exe" || lower == L"system informer.exe";
}

static void AddSystemInformerCandidate(std::vector<std::wstring>& candidates,
                                       const std::wstring& rawPath) {
    std::wstring path = RegistryPathToExecutable(rawPath);
    if (!LooksLikeSystemInformerExecutable(path)) return;
    for (const auto& existing : candidates) {
        if (_wcsicmp(existing.c_str(), path.c_str()) == 0) return;
    }
    candidates.push_back(path);
}

static void AddSystemInformerEnvironmentCandidate(std::vector<std::wstring>& candidates,
                                                   const wchar_t* variable,
                                                   const wchar_t* relative) {
    wchar_t base[32768]{};
    DWORD length = GetEnvironmentVariableW(variable, base, static_cast<DWORD>(ARRAYSIZE(base)));
    if (length == 0 || length >= ARRAYSIZE(base)) return;
    AddSystemInformerCandidate(candidates, JoinPath(base, relative));
}

static void AddSystemInformerAppPathCandidates(std::vector<std::wstring>& candidates,
                                                HKEY root, REGSAM view) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\SystemInformer.exe",
            0, KEY_READ | view, &key) != ERROR_SUCCESS) return;

    std::wstring value;
    if (ReadRegistryStringValue(key, nullptr, value)) AddSystemInformerCandidate(candidates, value);
    RegCloseKey(key);
}

static bool SystemInformerDisplayName(const std::wstring& name) {
    const std::wstring lower = LowerAscii(TrimWhitespace(name));
    return lower == L"system informer" || lower == L"systeminformer" ||
           lower.rfind(L"system informer ", 0) == 0 ||
           lower.rfind(L"systeminformer ", 0) == 0;
}

static void AddSystemInformerUninstallCandidates(std::vector<std::wstring>& candidates,
                                                  HKEY root, REGSAM view) {
    HKEY uninstall = nullptr;
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            0, KEY_READ | view, &uninstall) != ERROR_SUCCESS) return;

    for (DWORD index = 0;; ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;

        HKEY item = nullptr;
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;

        std::wstring displayName;
        if (ReadRegistryStringValue(item, L"DisplayName", displayName) &&
            SystemInformerDisplayName(displayName)) {
            std::wstring installLocation;
            if (ReadRegistryStringValue(item, L"InstallLocation", installLocation)) {
                installLocation = TrimWhitespace(installLocation);
                if (!installLocation.empty()) {
                    AddSystemInformerCandidate(candidates, JoinPath(installLocation, L"SystemInformer.exe"));
                    AddSystemInformerCandidate(candidates, JoinPath(installLocation, L"System Informer.exe"));
                }
            }

            std::wstring displayIcon;
            if (ReadRegistryStringValue(item, L"DisplayIcon", displayIcon))
                AddSystemInformerCandidate(candidates, displayIcon);
        }
        RegCloseKey(item);
    }
    RegCloseKey(uninstall);
}

static std::wstring FindInstalledSystemInformerPath() {
    std::vector<std::wstring> candidates;

    AddSystemInformerAppPathCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddSystemInformerAppPathCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddSystemInformerAppPathCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_64KEY);
    AddSystemInformerAppPathCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_32KEY);
    AddSystemInformerAppPathCandidates(candidates, HKEY_CURRENT_USER, 0);

    AddSystemInformerUninstallCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY);
    AddSystemInformerUninstallCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY);
    AddSystemInformerUninstallCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_64KEY);
    AddSystemInformerUninstallCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_32KEY);
    AddSystemInformerUninstallCandidates(candidates, HKEY_CURRENT_USER, 0);

    AddSystemInformerEnvironmentCandidate(candidates, L"ProgramW6432", L"SystemInformer\\SystemInformer.exe");
    AddSystemInformerEnvironmentCandidate(candidates, L"ProgramW6432", L"System Informer\\SystemInformer.exe");
    AddSystemInformerEnvironmentCandidate(candidates, L"ProgramFiles", L"SystemInformer\\SystemInformer.exe");
    AddSystemInformerEnvironmentCandidate(candidates, L"ProgramFiles", L"System Informer\\SystemInformer.exe");
    AddSystemInformerEnvironmentCandidate(candidates, L"ProgramFiles(x86)", L"SystemInformer\\SystemInformer.exe");
    AddSystemInformerEnvironmentCandidate(candidates, L"ProgramFiles(x86)", L"System Informer\\SystemInformer.exe");
    AddSystemInformerEnvironmentCandidate(candidates, L"LOCALAPPDATA", L"Programs\\SystemInformer\\SystemInformer.exe");
    AddSystemInformerEnvironmentCandidate(candidates, L"LOCALAPPDATA", L"Programs\\System Informer\\SystemInformer.exe");

    for (const auto& path : candidates) {
        if (FileExists(path)) return path;
    }
    return {};
}

static bool FindSystemInformerUninstallCommandInView(HKEY root, REGSAM view,
                                                      std::wstring& command) {
    HKEY uninstall = nullptr;
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            0, KEY_READ | view, &uninstall) != ERROR_SUCCESS) return false;

    bool found = false;
    for (DWORD index = 0; !found; ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;

        HKEY item = nullptr;
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;

        std::wstring displayName;
        if (ReadRegistryStringValue(item, L"DisplayName", displayName) &&
            SystemInformerDisplayName(displayName)) {
            // MSI products are removed through the documented Windows Installer
            // path. For non-MSI installs, use the publisher-registered quiet
            // command when available, then fall back to UninstallString.
            DWORD windowsInstaller = 0;
            const bool isMsi = ReadRegistryDwordValue(item, L"WindowsInstaller", windowsInstaller) &&
                               windowsInstaller != 0 && LooksLikeMsiProductCode(subName);
            if (isMsi) {
                command = L"msiexec.exe /X" + std::wstring(subName) + L" /qn /norestart";
            } else if (!ReadRegistryStringValue(item, L"QuietUninstallString", command)) {
                ReadRegistryStringValue(item, L"UninstallString", command);
            }
            found = !command.empty();
        }
        RegCloseKey(item);
    }
    RegCloseKey(uninstall);
    return found;
}

static bool FindSystemInformerUninstallCommand(std::wstring& command) {
    command.clear();
    return FindSystemInformerUninstallCommandInView(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_CURRENT_USER, KEY_WOW64_64KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_CURRENT_USER, KEY_WOW64_32KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_CURRENT_USER, 0, command);
}

static void SplitRegisteredCommand(const std::wstring& command,
                                   std::wstring& executable,
                                   std::wstring& arguments) {
    executable.clear();
    arguments.clear();
    std::wstring text = TrimWhitespace(command);
    if (text.empty()) return;

    size_t next = std::wstring::npos;
    if (text.front() == L'"') {
        size_t end = text.find(L'"', 1);
        if (end == std::wstring::npos) {
            executable = text.substr(1);
            return;
        }
        executable = text.substr(1, end - 1);
        next = end + 1;
    } else {
        // Registry uninstall strings are usually quoted, but some vendors store
        // an unquoted executable path containing spaces. Prefer the first .exe
        // boundary so such paths are parsed correctly without invoking cmd.exe.
        const std::wstring lower = LowerAscii(text);
        size_t exeEnd = lower.find(L".exe");
        if (exeEnd != std::wstring::npos) {
            exeEnd += 4;
            executable = text.substr(0, exeEnd);
            next = exeEnd;
        } else {
            size_t end = text.find_first_of(L" \t");
            executable = end == std::wstring::npos ? text : text.substr(0, end);
            next = end;
        }
    }

    if (next != std::wstring::npos)
        arguments = TrimWhitespace(text.substr(next));
}

// -----------------------------------------------------------------------------
// Recuva / FTK Imager installed-application integration.
// These helpers only read the standard App Paths / Uninstall registry entries
// and a few normal installation directories. They do not enumerate or kill
// processes by name and do not use cmd.exe / PowerShell.
// -----------------------------------------------------------------------------
static bool IsRecuvaItemIndex(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    return LowerAscii(kItems[itemIndex].name) == L"recuva";
}

static bool IsFtkImagerItemIndex(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    return LowerAscii(kItems[itemIndex].name) == L"ftk imager";
}

static bool RecuvaDisplayName(const std::wstring& name) {
    const std::wstring lower = LowerAscii(TrimWhitespace(name));
    return lower == L"recuva" || lower.rfind(L"recuva ", 0) == 0;
}

static bool FtkImagerDisplayName(const std::wstring& name) {
    const std::wstring lower = LowerAscii(TrimWhitespace(name));
    return lower == L"ftk imager" || lower.rfind(L"ftk imager ", 0) == 0 ||
           lower.rfind(L"exterro ftk imager", 0) == 0 ||
           lower.rfind(L"accessdata ftk imager", 0) == 0;
}

static bool LooksLikeRecuvaExecutable(const std::wstring& path) {
    if (path.empty() || !EndsWithI(path, L".exe")) return false;
    const std::wstring lower = LowerAscii(FileNameOnly(path));
    return lower == L"recuva.exe" || lower == L"recuva64.exe";
}

static bool LooksLikeFtkImagerExecutable(const std::wstring& path) {
    if (path.empty() || !EndsWithI(path, L".exe")) return false;
    const std::wstring lower = LowerAscii(FileNameOnly(path));
    return lower == L"ftk imager.exe" ||
           lower == L"ftkimager.exe" ||
           lower == L"ftk imager (x64).exe" ||
           lower == L"ftk imager (x86).exe";
}

typedef bool (*InstalledProductDisplayMatcher)(const std::wstring&);
typedef bool (*InstalledExecutableMatcher)(const std::wstring&);

static void AddInstalledProductCandidate(std::vector<std::wstring>& candidates,
                                         const std::wstring& rawPath,
                                         InstalledExecutableMatcher matcher) {
    std::wstring path = RegistryPathToExecutable(rawPath);
    if (!matcher || !matcher(path)) return;
    for (const auto& existing : candidates) {
        if (_wcsicmp(existing.c_str(), path.c_str()) == 0) return;
    }
    candidates.push_back(path);
}

static void AddInstalledEnvironmentCandidate(std::vector<std::wstring>& candidates,
                                             const wchar_t* variable,
                                             const wchar_t* relative,
                                             InstalledExecutableMatcher matcher) {
    wchar_t base[32768]{};
    DWORD length = GetEnvironmentVariableW(variable, base, static_cast<DWORD>(ARRAYSIZE(base)));
    if (length == 0 || length >= ARRAYSIZE(base)) return;
    AddInstalledProductCandidate(candidates, JoinPath(base, relative), matcher);
}

static void AddInstalledAppPathCandidate(std::vector<std::wstring>& candidates,
                                         HKEY root, REGSAM view,
                                         const wchar_t* executableName,
                                         InstalledExecutableMatcher matcher) {
    if (!executableName || !*executableName) return;
    const std::wstring keyPath =
        std::wstring(L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\") + executableName;
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, keyPath.c_str(), 0, KEY_READ | view, &key) != ERROR_SUCCESS) return;
    std::wstring value;
    if (ReadRegistryStringValue(key, nullptr, value))
        AddInstalledProductCandidate(candidates, value, matcher);
    RegCloseKey(key);
}

static void AddInstalledUninstallCandidates(std::vector<std::wstring>& candidates,
                                            HKEY root, REGSAM view,
                                            InstalledProductDisplayMatcher displayMatcher,
                                            InstalledExecutableMatcher executableMatcher,
                                            const std::initializer_list<const wchar_t*>& fileNames) {
    HKEY uninstall = nullptr;
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            0, KEY_READ | view, &uninstall) != ERROR_SUCCESS) return;

    for (DWORD index = 0;; ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;

        HKEY item = nullptr;
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;

        std::wstring displayName;
        if (ReadRegistryStringValue(item, L"DisplayName", displayName) &&
            displayMatcher && displayMatcher(displayName)) {
            std::wstring installLocation;
            if (ReadRegistryStringValue(item, L"InstallLocation", installLocation)) {
                installLocation = TrimWhitespace(installLocation);
                for (const wchar_t* fileName : fileNames) {
                    if (fileName && *fileName)
                        AddInstalledProductCandidate(candidates, JoinPath(installLocation, fileName), executableMatcher);
                }
            }

            std::wstring displayIcon;
            if (ReadRegistryStringValue(item, L"DisplayIcon", displayIcon))
                AddInstalledProductCandidate(candidates, displayIcon, executableMatcher);
        }
        RegCloseKey(item);
    }
    RegCloseKey(uninstall);
}

static bool FindInstalledProductUninstallCommandInView(
        HKEY root, REGSAM view,
        InstalledProductDisplayMatcher displayMatcher,
        std::wstring& command) {
    HKEY uninstall = nullptr;
    if (RegOpenKeyExW(root,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            0, KEY_READ | view, &uninstall) != ERROR_SUCCESS) return false;

    bool found = false;
    for (DWORD index = 0; !found; ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) continue;

        HKEY item = nullptr;
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;
        std::wstring displayName;
        if (ReadRegistryStringValue(item, L"DisplayName", displayName) &&
            displayMatcher && displayMatcher(displayName)) {
            // Prefer the documented Windows Installer path for MSI products.
            // This avoids relying on vendor bootstrapper paths and guarantees
            // that /I is not accidentally used instead of /X.
            DWORD windowsInstaller = 0;
            const bool isMsi = ReadRegistryDwordValue(item, L"WindowsInstaller", windowsInstaller) &&
                               windowsInstaller != 0 && LooksLikeMsiProductCode(subName);
            if (isMsi) {
                command = L"msiexec.exe /X" + std::wstring(subName) + L" /qn /norestart";
            } else if (!ReadRegistryStringValue(item, L"QuietUninstallString", command)) {
                ReadRegistryStringValue(item, L"UninstallString", command);
            }
            found = !command.empty();
        }
        RegCloseKey(item);
    }
    RegCloseKey(uninstall);
    return found;
}

static bool FindInstalledProductUninstallCommand(InstalledProductDisplayMatcher displayMatcher,
                                                 std::wstring& command) {
    command.clear();
    return FindInstalledProductUninstallCommandInView(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, displayMatcher, command) ||
           FindInstalledProductUninstallCommandInView(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, displayMatcher, command) ||
           FindInstalledProductUninstallCommandInView(HKEY_CURRENT_USER, KEY_WOW64_64KEY, displayMatcher, command) ||
           FindInstalledProductUninstallCommandInView(HKEY_CURRENT_USER, KEY_WOW64_32KEY, displayMatcher, command) ||
           FindInstalledProductUninstallCommandInView(HKEY_CURRENT_USER, 0, displayMatcher, command);
}

static std::wstring FindInstalledRecuvaPath() {
    std::vector<std::wstring> candidates;
    for (const wchar_t* exeName : { L"recuva64.exe", L"recuva.exe" }) {
        AddInstalledAppPathCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, exeName, LooksLikeRecuvaExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, exeName, LooksLikeRecuvaExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_CURRENT_USER, KEY_WOW64_64KEY, exeName, LooksLikeRecuvaExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_CURRENT_USER, KEY_WOW64_32KEY, exeName, LooksLikeRecuvaExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_CURRENT_USER, 0, exeName, LooksLikeRecuvaExecutable);
    }

    AddInstalledUninstallCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY,
                                    RecuvaDisplayName, LooksLikeRecuvaExecutable,
                                    { L"recuva64.exe", L"recuva.exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY,
                                    RecuvaDisplayName, LooksLikeRecuvaExecutable,
                                    { L"recuva64.exe", L"recuva.exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_64KEY,
                                    RecuvaDisplayName, LooksLikeRecuvaExecutable,
                                    { L"recuva64.exe", L"recuva.exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_32KEY,
                                    RecuvaDisplayName, LooksLikeRecuvaExecutable,
                                    { L"recuva64.exe", L"recuva.exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_CURRENT_USER, 0,
                                    RecuvaDisplayName, LooksLikeRecuvaExecutable,
                                    { L"recuva64.exe", L"recuva.exe" });

    AddInstalledEnvironmentCandidate(candidates, L"ProgramW6432", L"Recuva\\recuva64.exe", LooksLikeRecuvaExecutable);
    AddInstalledEnvironmentCandidate(candidates, L"ProgramW6432", L"Recuva\\recuva.exe", LooksLikeRecuvaExecutable);
    AddInstalledEnvironmentCandidate(candidates, L"ProgramFiles", L"Recuva\\recuva64.exe", LooksLikeRecuvaExecutable);
    AddInstalledEnvironmentCandidate(candidates, L"ProgramFiles", L"Recuva\\recuva.exe", LooksLikeRecuvaExecutable);
    AddInstalledEnvironmentCandidate(candidates, L"ProgramFiles(x86)", L"Recuva\\recuva.exe", LooksLikeRecuvaExecutable);
    AddInstalledEnvironmentCandidate(candidates, L"LOCALAPPDATA", L"Programs\\Recuva\\recuva64.exe", LooksLikeRecuvaExecutable);
    AddInstalledEnvironmentCandidate(candidates, L"LOCALAPPDATA", L"Programs\\Recuva\\recuva.exe", LooksLikeRecuvaExecutable);

    for (const auto& path : candidates) if (FileExists(path)) return path;
    return {};
}

static std::wstring FindFtkExecutableUnderVendorDirectory(const std::wstring& directory,
                                                           int depthRemaining) {
    if (directory.empty() || depthRemaining < 0 || !DirectoryExists(directory)) return {};

    const std::wstring mask = JoinPath(directory, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(mask.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return {};

    std::vector<std::wstring> childDirectories;
    std::wstring found;
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
            continue;
        const std::wstring child = JoinPath(directory, data.cFileName);
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0)
                childDirectories.push_back(child);
        } else if (LooksLikeFtkImagerExecutable(child)) {
            found = child;
            break;
        }
    } while (FindNextFileW(find, &data));
    FindClose(find);

    if (!found.empty()) return found;
    if (depthRemaining == 0) return {};
    for (const auto& child : childDirectories) {
        found = FindFtkExecutableUnderVendorDirectory(child, depthRemaining - 1);
        if (!found.empty()) return found;
    }
    return {};
}

static std::wstring FindInstalledFtkImagerPath() {
    std::vector<std::wstring> candidates;
    for (const wchar_t* exeName : { L"FTK Imager.exe", L"FTKImager.exe" }) {
        AddInstalledAppPathCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, exeName, LooksLikeFtkImagerExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, exeName, LooksLikeFtkImagerExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_CURRENT_USER, KEY_WOW64_64KEY, exeName, LooksLikeFtkImagerExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_CURRENT_USER, KEY_WOW64_32KEY, exeName, LooksLikeFtkImagerExecutable);
        AddInstalledAppPathCandidate(candidates, HKEY_CURRENT_USER, 0, exeName, LooksLikeFtkImagerExecutable);
    }

    AddInstalledUninstallCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY,
                                    FtkImagerDisplayName, LooksLikeFtkImagerExecutable,
                                    { L"FTK Imager.exe", L"FTKImager.exe", L"FTK Imager (x64).exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY,
                                    FtkImagerDisplayName, LooksLikeFtkImagerExecutable,
                                    { L"FTK Imager.exe", L"FTKImager.exe", L"FTK Imager (x64).exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_64KEY,
                                    FtkImagerDisplayName, LooksLikeFtkImagerExecutable,
                                    { L"FTK Imager.exe", L"FTKImager.exe", L"FTK Imager (x64).exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_CURRENT_USER, KEY_WOW64_32KEY,
                                    FtkImagerDisplayName, LooksLikeFtkImagerExecutable,
                                    { L"FTK Imager.exe", L"FTKImager.exe", L"FTK Imager (x64).exe" });
    AddInstalledUninstallCandidates(candidates, HKEY_CURRENT_USER, 0,
                                    FtkImagerDisplayName, LooksLikeFtkImagerExecutable,
                                    { L"FTK Imager.exe", L"FTKImager.exe", L"FTK Imager (x64).exe" });

    for (const wchar_t* variable : { L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)" }) {
        AddInstalledEnvironmentCandidate(candidates, variable, L"AccessData\\FTK Imager\\FTK Imager.exe", LooksLikeFtkImagerExecutable);
        AddInstalledEnvironmentCandidate(candidates, variable, L"AccessData\\FTK Imager\\FTKImager.exe", LooksLikeFtkImagerExecutable);
        AddInstalledEnvironmentCandidate(candidates, variable, L"Exterro\\FTK Imager\\FTK Imager.exe", LooksLikeFtkImagerExecutable);
        AddInstalledEnvironmentCandidate(candidates, variable, L"Exterro\\FTK Imager\\FTKImager.exe", LooksLikeFtkImagerExecutable);
        AddInstalledEnvironmentCandidate(candidates, variable, L"FTK Imager\\FTK Imager.exe", LooksLikeFtkImagerExecutable);
    }

    for (const auto& path : candidates) if (FileExists(path)) return path;

    // Some FTK Imager installers use a versioned subfolder and omit
    // InstallLocation/DisplayIcon. Search only the normal vendor directories,
    // with a small depth limit, instead of scanning Program Files globally.
    for (const wchar_t* variable : { L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)" }) {
        wchar_t base[32768]{};
        DWORD length = GetEnvironmentVariableW(variable, base, static_cast<DWORD>(ARRAYSIZE(base)));
        if (length == 0 || length >= ARRAYSIZE(base)) continue;
        for (const wchar_t* vendor : { L"AccessData", L"Exterro", L"FTK Imager" }) {
            const std::wstring found = FindFtkExecutableUnderVendorDirectory(JoinPath(base, vendor), 3);
            if (!found.empty()) return found;
        }
    }
    return {};
}

static void NormalizeMsiUninstallArguments(std::wstring& arguments) {
    std::wstring trimmed = TrimWhitespace(arguments);
    if (trimmed.size() >= 2 && (trimmed[0] == L'/' || trimmed[0] == L'-') &&
        (trimmed[1] == L'i' || trimmed[1] == L'I')) {
        trimmed[1] = L'X';
    }

    const std::wstring lower = LowerAscii(trimmed);
    if (lower.find(L"/q") == std::wstring::npos &&
        lower.find(L"-q") == std::wstring::npos) {
        if (!trimmed.empty()) trimmed += L" ";
        trimmed += L"/qn";
    }
    if (lower.find(L"/norestart") == std::wstring::npos &&
        lower.find(L"/forcerestart") == std::wstring::npos &&
        lower.find(L"/promptrestart") == std::wstring::npos) {
        if (!trimmed.empty()) trimmed += L" ";
        trimmed += L"/norestart";
    }
    arguments = trimmed;
}

static bool IsPathUnderDirectory(const std::wstring& path, const std::wstring& base) {
    if (path.empty() || base.empty() || path.size() < base.size()) return false;
    if (_wcsnicmp(path.c_str(), base.c_str(), base.size()) != 0) return false;
    if (path.size() == base.size()) return true;
    const wchar_t next = path[base.size()];
    return next == L'\\' || next == L'/';
}

static bool GetEnvironmentDirectory(const wchar_t* variable, std::wstring& out) {
    out.clear();
    wchar_t buffer[32768]{};
    DWORD length = GetEnvironmentVariableW(variable, buffer, static_cast<DWORD>(ARRAYSIZE(buffer)));
    if (length == 0 || length >= ARRAYSIZE(buffer)) return false;
    out.assign(buffer, length);
    while (!out.empty() && (out.back() == L'\\' || out.back() == L'/')) out.pop_back();
    return !out.empty();
}

static bool IsTrustedUninstallerPath(std::wstring& executable) {
    executable = TrimWhitespace(executable);
    if (executable.empty()) return false;

    const std::wstring fileName = LowerAscii(FileNameOnly(executable));
    static const wchar_t* forbidden[] = {
        L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"wscript.exe",
        L"cscript.exe", L"mshta.exe", L"rundll32.exe", L"regsvr32.exe"
    };
    for (const wchar_t* name : forbidden) {
        if (fileName == name) return false;
    }
    if (executable.size() >= 2 && executable[0] == L'\\' && executable[1] == L'\\')
        return false; // UNC paths are never accepted from UninstallString.

    if (fileName == L"msiexec.exe" || fileName == L"msiexec") {
        wchar_t systemDir[MAX_PATH]{};
        const UINT length = GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir));
        if (length == 0 || length >= ARRAYSIZE(systemDir)) return false;
        executable = JoinPath(systemDir, L"msiexec.exe");
        return FileExists(executable);
    }

    wchar_t fullBuffer[32768]{};
    DWORD fullLength = GetFullPathNameW(executable.c_str(), ARRAYSIZE(fullBuffer), fullBuffer, nullptr);
    if (fullLength == 0 || fullLength >= ARRAYSIZE(fullBuffer)) return false;
    std::wstring full(fullBuffer, fullLength);
    if (full.size() < 3 || full[1] != L':' || (full[2] != L'\\' && full[2] != L'/')) return false;

    std::wstring programW6432, programFiles, programFilesX86, localAppData, programData;
    GetEnvironmentDirectory(L"ProgramW6432", programW6432);
    GetEnvironmentDirectory(L"ProgramFiles", programFiles);
    GetEnvironmentDirectory(L"ProgramFiles(x86)", programFilesX86);
    GetEnvironmentDirectory(L"LOCALAPPDATA", localAppData);
    GetEnvironmentDirectory(L"ProgramData", programData);
    const std::wstring localPrograms = localAppData.empty() ? std::wstring() : JoinPath(localAppData, L"Programs");
    const std::wstring packageCache = programData.empty() ? std::wstring() : JoinPath(programData, L"Package Cache");

    if (!IsPathUnderDirectory(full, programW6432) &&
        !IsPathUnderDirectory(full, programFiles) &&
        !IsPathUnderDirectory(full, programFilesX86) &&
        !IsPathUnderDirectory(full, localPrograms) &&
        !IsPathUnderDirectory(full, packageCache)) {
        return false;
    }
    if (!FileExists(full)) return false;
    executable.swap(full);
    return true;
}

static bool ShouldElevateTrustedUninstaller(const std::wstring& executable) {
    const std::wstring fileName = LowerAscii(FileNameOnly(executable));
    if (fileName == L"msiexec.exe" || fileName == L"msiexec") return true;

    std::wstring programW6432, programFiles, programFilesX86, programData;
    GetEnvironmentDirectory(L"ProgramW6432", programW6432);
    GetEnvironmentDirectory(L"ProgramFiles", programFiles);
    GetEnvironmentDirectory(L"ProgramFiles(x86)", programFilesX86);
    GetEnvironmentDirectory(L"ProgramData", programData);
    const std::wstring packageCache = programData.empty() ? std::wstring() : JoinPath(programData, L"Package Cache");

    return IsPathUnderDirectory(executable, programW6432) ||
           IsPathUnderDirectory(executable, programFiles) ||
           IsPathUnderDirectory(executable, programFilesX86) ||
           IsPathUnderDirectory(executable, packageCache);
}

static bool LaunchRegisteredCommandNoWait(const wchar_t* displayLabel,
                                          const std::wstring& command,
                                          std::wstring& error) {
    error.clear();
    std::wstring executable, arguments;
    SplitRegisteredCommand(command, executable, arguments);
    if (executable.empty()) {
        error = L"В Windows не найдена корректная команда удаления " +
                std::wstring(displayLabel) + L".";
        return false;
    }
    if (!IsTrustedUninstallerPath(executable)) {
        error = L"Windows зарегистрировала небезопасный путь деинсталлятора " +
                std::wstring(displayLabel) + L". Запуск заблокирован.";
        return false;
    }

    const std::wstring exeName = LowerAscii(FileNameOnly(executable));
    if (exeName == L"msiexec.exe" || exeName == L"msiexec")
        NormalizeMsiUninstallArguments(arguments);

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.hwnd = g_mainWindow;
    // System-wide uninstallers need elevation to actually remove files and
    // services. This is the normal Windows UAC path, not a bypass. Per-user
    // uninstallers under LOCALAPPDATA continue to run without elevation.
    sei.lpVerb = ShouldElevateTrustedUninstaller(executable) ? L"runas" : L"open";
    sei.lpFile = executable.c_str();
    sei.lpParameters = arguments.empty() ? nullptr : arguments.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        error = L"Не удалось запустить штатный деинсталлятор " +
                std::wstring(displayLabel) + L": " + Win32ErrorText(GetLastError());
        return false;
    }

    // The uninstaller continues independently. HolyCheck must never block its
    // GUI while a vendor uninstaller is open or while a UAC prompt is pending.
    if (sei.hProcess) CloseHandle(sei.hProcess);
    return true;
}

static bool LaunchRegisteredSystemInformerUninstallerNoWait(std::wstring& error) {
    std::wstring command;
    if (!FindSystemInformerUninstallCommand(command)) {
        error = L"System Informer найден, но Windows не содержит зарегистрированной команды удаления.";
        return false;
    }
    return LaunchRegisteredCommandNoWait(L"System Informer", command, error);
}

static bool LaunchRegisteredProductUninstallerNoWait(
        const wchar_t* displayLabel,
        InstalledProductDisplayMatcher displayMatcher,
        std::wstring& error) {
    std::wstring command;
    if (!FindInstalledProductUninstallCommand(displayMatcher, command)) {
        error = std::wstring(displayLabel) +
                L" найден, но Windows не содержит зарегистрированной команды удаления.";
        return false;
    }
    return LaunchRegisteredCommandNoWait(displayLabel, command, error);
}

static bool LaunchRegisteredRecuvaUninstallerNoWait(std::wstring& error) {
    return LaunchRegisteredProductUninstallerNoWait(L"Recuva", RecuvaDisplayName, error);
}

static bool LaunchRegisteredFtkImagerUninstallerNoWait(std::wstring& error) {
    return LaunchRegisteredProductUninstallerNoWait(L"FTK Imager", FtkImagerDisplayName, error);
}

static bool IsItemAlreadyAvailable(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    if (IsSystemInformerItemIndex(itemIndex) && !FindInstalledSystemInformerPath().empty())
        return true;
    if (IsRecuvaItemIndex(itemIndex) && !FindInstalledRecuvaPath().empty())
        return true;
    if (IsFtkImagerItemIndex(itemIndex) && !FindInstalledFtkImagerPath().empty())
        return true;
    return FileExists(ItemPath(itemIndex));
}

// Drawing runs many times per second. Installed-program detection enumerates
// several Uninstall registry branches, so cache it briefly instead of doing
// registry I/O for every tile on every repaint.
static std::mutex g_availabilityCacheMutex;
static std::array<int, kItemCount> g_availabilityCache{}; // 0 unknown, 1 yes, -1 no
static std::array<ULONGLONG, kItemCount> g_availabilityCacheTicks{};

static void InvalidateAvailabilityCache(int itemIndex = -1) {
    std::lock_guard<std::mutex> lock(g_availabilityCacheMutex);
    if (itemIndex >= 0 && static_cast<size_t>(itemIndex) < kItemCount) {
        g_availabilityCache[static_cast<size_t>(itemIndex)] = 0;
        g_availabilityCacheTicks[static_cast<size_t>(itemIndex)] = 0;
        return;
    }
    g_availabilityCache.fill(0);
    g_availabilityCacheTicks.fill(0);
}

static bool IsItemAlreadyAvailableCached(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    const size_t index = static_cast<size_t>(itemIndex);
    const ULONGLONG now = GetTickCount64();
    {
        std::lock_guard<std::mutex> lock(g_availabilityCacheMutex);
        if (g_availabilityCache[index] != 0 &&
            now - g_availabilityCacheTicks[index] <= 2000ULL) {
            return g_availabilityCache[index] > 0;
        }
    }

    const bool available = IsItemAlreadyAvailable(itemIndex);
    {
        std::lock_guard<std::mutex> lock(g_availabilityCacheMutex);
        g_availabilityCache[index] = available ? 1 : -1;
        g_availabilityCacheTicks[index] = now;
    }
    return available;
}

// ZIP распаковывается штатным Shell Namespace API Windows.
// Никакие PowerShell/cmd/tar/7z процессы для распаковки не запускаются.
static bool ExtractZipWithWindowsShell(const std::wstring& zipPath,
                                       const std::wstring& destination,
                                       std::wstring& error) {
    if (!FileExists(zipPath)) {
        error = L"Архив не найден.";
        return false;
    }

    if (!EnsureDirectory(g_appDir) || !EnsureDirectory(g_extractDir) || !EnsureDirectory(destination)) {
        error = L"Не удалось создать папку для распаковки: " + Win32ErrorText(GetLastError());
        return false;
    }

    IShellDispatch* shell = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_Shell, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&shell));
    if (FAILED(hr) || !shell) {
        error = L"Не удалось открыть Windows Shell для распаковки.";
        return false;
    }

    VARIANT zipVariant{};
    VARIANT destVariant{};
    VariantInit(&zipVariant);
    VariantInit(&destVariant);
    zipVariant.vt = VT_BSTR;
    destVariant.vt = VT_BSTR;
    zipVariant.bstrVal = SysAllocString(zipPath.c_str());
    destVariant.bstrVal = SysAllocString(destination.c_str());

    if (!zipVariant.bstrVal || !destVariant.bstrVal) {
        VariantClear(&zipVariant);
        VariantClear(&destVariant);
        shell->Release();
        error = L"Недостаточно памяти для распаковки.";
        return false;
    }

    Folder* zipFolder = nullptr;
    Folder* destFolder = nullptr;
    hr = shell->NameSpace(zipVariant, &zipFolder);
    if (SUCCEEDED(hr)) hr = shell->NameSpace(destVariant, &destFolder);

    if (FAILED(hr) || !zipFolder || !destFolder) {
        if (zipFolder) zipFolder->Release();
        if (destFolder) destFolder->Release();
        VariantClear(&zipVariant);
        VariantClear(&destVariant);
        shell->Release();
        error = L"Windows не смогла открыть ZIP как архив.";
        return false;
    }

    FolderItems* items = nullptr;
    hr = zipFolder->Items(&items);
    if (FAILED(hr) || !items) {
        zipFolder->Release();
        destFolder->Release();
        VariantClear(&zipVariant);
        VariantClear(&destVariant);
        shell->Release();
        error = L"Не удалось прочитать содержимое ZIP.";
        return false;
    }

    VARIANT itemsVariant{};
    VARIANT optionsVariant{};
    VariantInit(&itemsVariant);
    VariantInit(&optionsVariant);
    itemsVariant.vt = VT_DISPATCH;
    itemsVariant.pdispVal = items;
    optionsVariant.vt = VT_I4;
    optionsVariant.lVal = FOF_NOCONFIRMATION |
                          FOF_SILENT |
                          FOF_NOERRORUI |
                          FOF_NOCONFIRMMKDIR;

    hr = destFolder->CopyHere(itemsVariant, optionsVariant);

    VariantClear(&itemsVariant);
    VariantClear(&optionsVariant);
    zipFolder->Release();
    destFolder->Release();
    VariantClear(&zipVariant);
    VariantClear(&destVariant);
    shell->Release();

    if (FAILED(hr)) {
        error = L"Windows не смогла начать распаковку ZIP.";
        return false;
    }
    return true;
}

struct DirectoryMeasure {
    unsigned long long bytes = 0;
    unsigned long long files = 0;
};

static void MeasureDirectoryTree(const std::wstring& directory, DirectoryMeasure& measure) {
    const std::wstring mask = JoinPath(directory, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(mask.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        const std::wstring child = JoinPath(directory, data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            MeasureDirectoryTree(child, measure);
        } else {
            ++measure.files;
            measure.bytes += (static_cast<unsigned long long>(data.nFileSizeHigh) << 32) |
                             static_cast<unsigned long long>(data.nFileSizeLow);
        }
    } while (FindNextFileW(find, &data));

    FindClose(find);
}

static bool WaitForExtractionToSettle(const std::wstring& destination, DWORD timeoutMs) {
    const ULONGLONG start = GetTickCount64();
    DirectoryMeasure previous{};
    int stableSamples = 0;

    // Windows Shell распаковывает CopyHere асинхронно. Раньше здесь была
    // искусственная пауза минимум 2 секунды. Для быстрого открытия достаточно
    // дождаться, когда размер и число файлов не меняются примерно 0.9-1.1 с.
    constexpr DWORD kPollMs = 180;
    constexpr int kStableSamplesNeeded = 6;
    constexpr ULONGLONG kMinimumElapsedMs = 650ULL;

    while (GetTickCount64() - start < timeoutMs) {
        DirectoryMeasure current{};
        MeasureDirectoryTree(destination, current);

        if (current.files > 0 && current.files == previous.files && current.bytes == previous.bytes) {
            ++stableSamples;
        } else {
            stableSamples = 0;
        }
        previous = current;

        if (GetTickCount64() - start >= kMinimumElapsedMs &&
            stableSamples >= kStableSamplesNeeded) {
            return true;
        }
        Sleep(kPollMs);
    }
    return false;
}

static std::wstring FileNameOnly(const std::wstring& path) {
    const size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? path : path.substr(pos + 1);
}

static std::wstring FileStemOnly(const std::wstring& path) {
    std::wstring file = FileNameOnly(path);
    const size_t dot = file.find_last_of(L'.');
    if (dot != std::wstring::npos) file.resize(dot);
    return file;
}

static std::wstring NormalizeLaunchKey(const std::wstring& value) {
    std::wstring out;
    out.reserve(value.size());
    for (wchar_t ch : LowerAscii(value)) {
        if ((ch >= L'a' && ch <= L'z') || (ch >= L'0' && ch <= L'9')) out.push_back(ch);
    }
    return out;
}

static void CollectExecutablesRecursive(const std::wstring& directory,
                                        std::vector<std::wstring>& out,
                                        int depth = 0) {
    if (depth > 10) return;
    const std::wstring mask = JoinPath(directory, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(mask.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return;

    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        const std::wstring child = JoinPath(directory, data.cFileName);
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            CollectExecutablesRecursive(child, out, depth + 1);
        } else if (EndsWithI(data.cFileName, L".exe")) {
            out.push_back(child);
        }
    } while (FindNextFileW(find, &data));

    FindClose(find);
}

static const wchar_t* PreferredArchiveExecutable(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return nullptr;
    const std::wstring name = LowerAscii(kItems[itemIndex].name);

    if (name == L"everything") return L"Everything64.exe";
    if (name == L"recentfilesview") return L"RecentFilesView.exe";
    if (name == L"lastactivityview") return L"LastActivityView.exe";
    if (name == L"executedprogramslist") return L"ExecutedProgramsList.exe";
    if (name == L"regscanner") return L"RegScanner.exe";
    if (name == L"browserdownloadsview") return L"BrowserDownloadsView.exe";
    if (name == L"usbdrivelog") return L"USBDriveLog.exe";
    if (name == L"usbdeview") return L"USBDeview.exe";
    if (name == L"registryexplorer") return L"RegistryExplorer.exe";
    if (name == L"jumplistexplorer") return L"JumpListExplorer.exe";
    if (name == L"simpleunlocker") return L"SimpleUnlocker.exe";
    if (name == L"winprefetchview") return L"WinPrefetchView.exe";
    if (name == L"detect it easy") return L"die.exe";
    if (name == L"browsinghistoryview") return L"BrowsingHistoryView.exe";
    if (name == L"alternatestreamview") return L"AlternateStreamView.exe";
    if (name == L"windeflogview") return L"WinDefLogView.exe";
    if (name == L"volatilityworkbench") return L"VolatilityWorkbench.exe";
    if (name == L"ftk imager") return L"Exterro_FTK_Imager_(x64).exe";
    return nullptr;
}

static int ExecutableCandidateScore(int itemIndex, const std::wstring& path) {
    const std::wstring itemKey = NormalizeLaunchKey(kItems[itemIndex].name);
    const std::wstring stemKey = NormalizeLaunchKey(FileStemOnly(path));
    const std::wstring lowerName = LowerAscii(FileNameOnly(path));

    int score = 0;
    const wchar_t* preferred = PreferredArchiveExecutable(itemIndex);
    if (preferred && _wcsicmp(FileNameOnly(path).c_str(), preferred) == 0) score += 100000;
    if (!itemKey.empty() && stemKey == itemKey) score += 10000;
    if (!itemKey.empty() && stemKey.find(itemKey) != std::wstring::npos) score += 5000;
    if (stemKey.size() >= 4 && itemKey.find(stemKey) != std::wstring::npos) score += 2500;

    if (lowerName.find(L"uninstall") != std::wstring::npos ||
        lowerName.find(L"unins") != std::wstring::npos ||
        lowerName.find(L"updater") != std::wstring::npos ||
        lowerName.find(L"crash") != std::wstring::npos ||
        lowerName.find(L"reporter") != std::wstring::npos ||
        lowerName.find(L"helper") != std::wstring::npos) {
        score -= 4000;
    }

    int separators = 0;
    for (wchar_t ch : path) if (ch == L'\\' || ch == L'/') ++separators;
    score -= separators * 5;
    return score;
}

static std::mutex g_launchPathCacheMutex;
static std::vector<std::wstring> g_launchPathCache(kItemCount);
static std::vector<std::wstring> g_launchHashCache(kItemCount);

static void ClearCachedLaunchPath(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return;
    std::lock_guard<std::mutex> lock(g_launchPathCacheMutex);
    g_launchPathCache[static_cast<size_t>(itemIndex)].clear();
    g_launchHashCache[static_cast<size_t>(itemIndex)].clear();
}

static std::wstring GetCachedLaunchPath(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return {};
    const size_t index = static_cast<size_t>(itemIndex);
    std::wstring cachedPath;
    std::wstring cachedHash;
    {
        std::lock_guard<std::mutex> lock(g_launchPathCacheMutex);
        cachedPath = g_launchPathCache[index];
        cachedHash = g_launchHashCache[index];
    }
    if (cachedPath.empty() || cachedHash.empty() || !FileExists(cachedPath)) {
        ClearCachedLaunchPath(itemIndex);
        return {};
    }

    // The extracted directory is user-writable. Re-hash the executable before
    // every later launch so a same-user process cannot silently replace it.
    std::wstring actualHash;
    if (!GetFileSha256Hex(cachedPath, actualHash) ||
        _wcsicmp(actualHash.c_str(), cachedHash.c_str()) != 0) {
        ClearCachedLaunchPath(itemIndex);
        return {};
    }
    return cachedPath;
}

static bool SetCachedLaunchPath(int itemIndex, const std::wstring& path) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount || !FileExists(path)) return false;
    std::wstring hash;
    if (!GetFileSha256Hex(path, hash)) return false;
    std::lock_guard<std::mutex> lock(g_launchPathCacheMutex);
    const size_t index = static_cast<size_t>(itemIndex);
    g_launchPathCache[index] = path;
    g_launchHashCache[index] = hash;
    return true;
}

static bool VerifyCachedExtractedPathForOpen(int itemIndex, const std::wstring& path,
                                             std::wstring& error) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    std::wstring cachedPath, expectedHash;
    {
        std::lock_guard<std::mutex> lock(g_launchPathCacheMutex);
        const size_t index = static_cast<size_t>(itemIndex);
        cachedPath = g_launchPathCache[index];
        expectedHash = g_launchHashCache[index];
    }
    if (cachedPath.empty() || expectedHash.empty() || _wcsicmp(cachedPath.c_str(), path.c_str()) != 0) {
        error = L"Распакованный файл не прошёл проверку целостности.";
        return false;
    }
    std::wstring actualHash;
    if (!GetFileSha256Hex(path, actualHash) ||
        _wcsicmp(actualHash.c_str(), expectedHash.c_str()) != 0) {
        error = L"Распакованный файл был изменён после распаковки и не будет запущен.";
        return false;
    }
    return true;
}

static std::wstring FindNamedExecutableRecursive(const std::wstring& directory,
                                                  const wchar_t* fileName,
                                                  int depth = 0) {
    if (!fileName || !*fileName || depth > 10 || !DirectoryExists(directory)) return {};

    // Самый частый случай: EXE лежит прямо в корне распакованной папки.
    const std::wstring direct = JoinPath(directory, fileName);
    if (FileExists(direct)) return direct;

    const std::wstring mask = JoinPath(directory, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(mask.c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return {};

    std::wstring result;
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        result = FindNamedExecutableRecursive(JoinPath(directory, data.cFileName), fileName, depth + 1);
        if (!result.empty()) break;
    } while (FindNextFileW(find, &data));

    FindClose(find);
    return result;
}

static std::wstring FindBestExtractedExecutable(int itemIndex, const std::wstring& directory) {
    if (!DirectoryExists(directory)) return {};

    // Повторное открытие ZIP-программ не должно снова обходить всю папку.
    std::wstring cached = GetCachedLaunchPath(itemIndex);
    if (!cached.empty()) return cached;

    // Для известных архивов сначала ищем точное имя нужной программы и
    // останавливаем обход сразу после первого совпадения.
    const wchar_t* preferred = PreferredArchiveExecutable(itemIndex);
    if (preferred) {
        std::wstring exact = FindNamedExecutableRecursive(directory, preferred);
        if (!exact.empty() && SetCachedLaunchPath(itemIndex, exact)) {
            return exact;
        }
    }

    // Резервный поиск нужен только для архивов с неизвестной структурой.
    std::vector<std::wstring> candidates;
    CollectExecutablesRecursive(directory, candidates);
    if (candidates.empty()) return {};

    size_t bestIndex = 0;
    int bestScore = ExecutableCandidateScore(itemIndex, candidates[0]);
    for (size_t i = 1; i < candidates.size(); ++i) {
        const int score = ExecutableCandidateScore(itemIndex, candidates[i]);
        if (score > bestScore) {
            bestScore = score;
            bestIndex = i;
        }
    }

    if (SetCachedLaunchPath(itemIndex, candidates[bestIndex]))
        return candidates[bestIndex];
    return {};
}

static void StartArchiveExtractionAndOpen(int itemIndex) {
    if (!MarkBusy(itemIndex)) return;
    RefreshItemButtons(itemIndex);

    const std::wstring zipPath = ItemPath(itemIndex);
    const std::wstring destination = ItemExtractDirectory(itemIndex);
    HWND target = g_mainWindow;

    std::thread([target, itemIndex, zipPath, destination]() {
        auto message = std::make_unique<OpenReadyMessage>();
        message->itemIndex = itemIndex;

        HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        std::wstring error;
        bool ok = !zipPath.empty() && !destination.empty();

        // Re-check the pinned archive immediately before extraction. Also
        // remove old extracted content so files from different versions can
        // never be mixed together.
        if (ok) ok = VerifyPinnedPayloadForItem(itemIndex, zipPath, error);
        if (ok) {
            ClearCachedLaunchPath(itemIndex);
            if (DirectoryExists(destination) && !DeleteDirectoryTreeNoReparse(destination)) {
                ok = false;
                error = L"Не удалось очистить старую папку распаковки.";
            }
        }
        if (ok) ok = ExtractZipWithWindowsShell(zipPath, destination, error);

        if (ok && !WaitForExtractionToSettle(destination, 60000)) {
            ok = false;
            error = L"Распаковка не завершилась вовремя.";
        }

        if (ok) {
            message->path = FindBestExtractedExecutable(itemIndex, destination);
            if (message->path.empty()) {
                ok = false;
                error = L"В распакованном архиве не найден исполняемый EXE-файл.";
            }
        }

        message->ok = ok;
        message->error = error;
        if (SUCCEEDED(com)) CoUninitialize();

        if (!PostOpenReadyResult(target, std::move(message))) {
            MarkIdle(itemIndex);
        }
    }).detach();
}

void OpenDownloadedItem(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return;
    if (g_deleteAllBusy.load() || IsBusy(itemIndex)) return;

    // If System Informer is already installed, always launch the installed
    // application instead of re-opening its setup executable.
    if (IsSystemInformerItemIndex(itemIndex)) {
        const std::wstring installed = FindInstalledSystemInformerPath();
        if (!installed.empty()) {
            std::wstring launchError;
            if (!OpenTrackedPath(itemIndex, installed, launchError))
                MessageBoxW(g_mainWindow, launchError.c_str(), L"HolyCheck", MB_OK | MB_ICONERROR);
            return;
        }
    }

    if (IsRecuvaItemIndex(itemIndex)) {
        const std::wstring installed = FindInstalledRecuvaPath();
        if (!installed.empty()) {
            std::wstring launchError;
            if (!OpenTrackedPath(itemIndex, installed, launchError))
                MessageBoxW(g_mainWindow, launchError.c_str(), L"HolyCheck", MB_OK | MB_ICONERROR);
            return;
        }
    }

    if (IsFtkImagerItemIndex(itemIndex)) {
        const std::wstring installed = FindInstalledFtkImagerPath();
        if (!installed.empty()) {
            std::wstring launchError;
            if (!OpenTrackedPath(itemIndex, installed, launchError))
                MessageBoxW(g_mainWindow, launchError.c_str(), L"HolyCheck", MB_OK | MB_ICONERROR);
            return;
        }
    }

    const std::wstring path = ItemPath(itemIndex);
    if (path.empty() || !FileExists(path)) return;

    if (!BasicPayloadCheck(path, kItems[itemIndex].file)) {
        MessageBoxW(g_mainWindow,
                    L"Файл не прошёл проверку формата и не будет открыт.",
                    L"HolyCheck", MB_OK | MB_ICONERROR);
        return;
    }

    std::wstring error;
    if (!VerifyPinnedPayloadForItem(itemIndex, path, error)) {
        MessageBoxW(g_mainWindow, error.c_str(), L"HolyCheck", MB_OK | MB_ICONERROR);
        return;
    }

    if (EndsWithI(kItems[itemIndex].file, L".zip")) {
        if (!InitDownloadDirectory()) {
            MessageBoxW(g_mainWindow, L"Не удалось подготовить папки HolyCheck.",
                        L"HolyCheck", MB_OK | MB_ICONERROR);
            return;
        }

        const std::wstring destination = ItemExtractDirectory(itemIndex);
        // Only a path produced and hashed by this running HolyCheck instance is
        // reused. After restart we re-extract from the verified archive rather
        // than trusting stale user-writable Extracted content.
        std::wstring executable = GetCachedLaunchPath(itemIndex);
        if (!executable.empty()) {
            if (!OpenTrackedPath(itemIndex, executable, error))
                MessageBoxW(g_mainWindow, error.c_str(), L"HolyCheck", MB_OK | MB_ICONERROR);
            return;
        }

        StartArchiveExtractionAndOpen(itemIndex);
        return;
    }

    if (!OpenTrackedPath(itemIndex, path, error)) {
        MessageBoxW(g_mainWindow, error.c_str(), L"HolyCheck", MB_OK | MB_ICONERROR);
    }
}
