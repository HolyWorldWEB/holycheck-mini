static std::wstring ItemExtractDirectory(int itemIndex) {
    if(itemIndex<0||static_cast<size_t>(itemIndex)>=kItemCount||kItems[itemIndex].website)return {};
    const auto parent=ItemDirectory(itemIndex);
    if(parent.empty())return {};
    const auto folder=HolyStorage::ArchiveFolderName(kItems[itemIndex].file);
    if(folder.empty())return parent; // Non-archive payloads unchanged.
    return JoinPath(parent,folder);
}

#include "zip_extract.inc"

static bool EndsWithI(const std::wstring& value, const wchar_t* suffix) {
    if (!suffix) return false;
    std::wstring a = LowerAscii(value);
    std::wstring b = LowerAscii(suffix);
    return a.size() >= b.size() && a.compare(a.size() - b.size(), b.size(), b) == 0;
}


static bool IsProcessStillRunning(HANDLE process) {
    // Unknown liveness must not be treated as an exited process during cleanup.
    return process && WaitForSingleObject(process, 0) != WAIT_OBJECT_0;
}

static void CleanupExitedTrackedProcesses() {
    std::lock_guard<std::mutex> lock(g_processMutex);
    for (size_t i = 0; i < g_launchedProcesses.size();) {
        if (!IsProcessStillRunning(g_launchedProcesses[i].process)) {
            FullLog(L"PROCESS release exited tracked item="+std::to_wstring(g_launchedProcesses[i].itemIndex)+L" pid="+std::to_wstring(g_launchedProcesses[i].pid));
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

static bool ActivateAlreadyRunningItem(int itemIndex, const std::wstring& path) {
    CleanupExitedTrackedProcesses();

    DWORD pid = 0;
    {
        std::lock_guard<std::mutex> lock(g_processMutex);
        for (const auto& entry : g_launchedProcesses) {
            if (entry.itemIndex == itemIndex && (path.empty() || _wcsicmp(entry.path.c_str(), path.c_str()) == 0) && IsProcessStillRunning(entry.process)) {
                pid = entry.pid;
                break;
            }
        }
    }

    if (!pid) return false;
    BringTrackedProcessToFront(pid);
    return true;
}

static void TrackLaunchedProcess(int itemIndex, const std::wstring& path, HANDLE process) {
    if (!process) return;
    const DWORD pid = GetProcessId(process);
    if (!pid) {
        CloseHandle(process);
        return;
    }

    std::lock_guard<std::mutex> lock(g_processMutex);
    g_launchedProcesses.push_back({ itemIndex, process, pid, path });
}

static bool CaptureApprovedLaunchTarget(const std::wstring& path,ApprovedLaunchTarget& target) {
    HANDLE h=CreateFileW(path.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h==INVALID_HANDLE_VALUE)return false;
    HandleSet handles;handles.Add(h);BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(h,&info)||(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))return false;
    wchar_t canonical[32768]{};
    const DWORD n=GetFinalPathNameByHandleW(h,canonical,ARRAYSIZE(canonical),FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if(!n||n>=ARRAYSIZE(canonical))return false;
    std::wstring full(canonical,n);
    if(full.compare(0,4,LR"(\\?\)")==0)full.erase(0,4);
    if(!HolyFiles::LocalPath(full))return false;
    target.path=std::move(full);target.identity=info;target.valid=true;return true;
}

static bool IsRegistryExplorerItemIndex(int itemIndex) {
    return itemIndex >= 0 &&
           static_cast<size_t>(itemIndex) < kItemCount &&
           _wcsicmp(kItems[itemIndex].name, L"RegistryExplorer") == 0;
}

static bool IsPathUnderDirectory(const std::wstring& path, const std::wstring& base);
static bool IsTrustedUninstallerPath(std::wstring& executable, std::wstring* diagnostic = nullptr, bool enforceKnownRoot = true);
static bool VerifyInstalledProgramTrust(int itemIndex, const std::wstring& path, std::wstring& error);

static bool OpenTrackedPath(int itemIndex, const std::wstring& path, std::wstring& error) {
    if(itemIndex<0||static_cast<size_t>(itemIndex)>=kItemCount) {
        error=L"Некорректный элемент каталога запуска.";return false;
    }
    if(kItems[itemIndex].website) {
        error=L"Для кнопки-ссылки запуск локального файла запрещён.";return false;
    }
    // Applies before activation of an already running instance as well.
    if(RejectReportedPayload(itemIndex,error))return false;
    if (path.empty() || !FileExists(path)) {
        error = L"Файл для запуска не найден.";
        return false;
    }

    // Не создаём второй экземпляр по повторному клику, пока ранее открытый
    // процесс этой же программы ещё работает.
    if (ActivateAlreadyRunningItem(itemIndex, path)) return true;

    // Keep a read handle without write/delete sharing until ShellExecuteExW
    // has opened the target. This narrows the check-to-launch race: another
    // same-user process cannot replace the file between verification and launch.
    HandleSet launchLocks;
    if (!LockRegularFile(path, launchLocks)) {
        error = L"Не удалось заблокировать файл на время запуска: " +
                Win32ErrorText(GetLastError());
        return false;
    }

    // Verify while the no-write/no-delete-sharing lock is held. This closes
    // the remaining local replacement window between the earlier check and
    // ShellExecuteExW.
    const std::wstring downloadedPath = ItemPath(itemIndex);
    const std::wstring extractedRoot = ItemExtractDirectory(itemIndex);
    bool integrityOk = false;
    if (!downloadedPath.empty() && _wcsicmp(downloadedPath.c_str(), path.c_str()) == 0) {
        integrityOk = VerifyPinnedPayloadForItem(itemIndex, path, error);
    } else if (!extractedRoot.empty() && IsPathUnderDirectory(path, extractedRoot)) {
        integrityOk = LockVerifiedExtractedTree(itemIndex, path, launchLocks, error);
    } else {
        integrityOk = VerifyInstalledProgramTrust(itemIndex, path, error);
    }
    if (integrityOk && EndsWithI(path, L".exe")) integrityOk = IsValidPeExecutable(path, &error);
    if (!integrityOk) {
        if (error.empty()) error = L"Некорректный исполняемый файл.";
        return false;
    }

    // Registry Explorer для полноценного доступа к системным веткам реестра
    // запускается через штатный Windows UAC. Никакого обхода UAC нет: пользователь
    // видит обычное системное окно подтверждения. Остальные программы запускаются
    // с обычными правами.
    const bool elevate = IsRegistryExplorerItemIndex(itemIndex);

    ApprovedLaunchTarget approved;
    if(!CaptureApprovedLaunchTarget(path,approved)) {
        error=L"Не удалось сохранить идентичность запускаемого приложения.";return false;
    }

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    sei.hwnd = g_mainWindow;
    sei.lpVerb = elevate ? L"runas" : L"open";
    sei.lpFile = path.c_str();
    const auto workingDirectory = HolyInstalled::Parent(path);
    sei.lpDirectory = workingDirectory.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (g_cancelRequested.load()) { error = L"Операция отменена до запуска."; return false; }
    if (!ShellExecuteExW(&sei)) {
        const DWORD code = GetLastError();
        if (elevate && code == ERROR_CANCELLED)
            error = L"Запуск Registry Explorer от имени администратора отменён.";
        else
            error = L"Windows не смогла открыть программу: " + Win32ErrorText(code);
        return false;
    }

    FullLog(L"LAUNCH success item=" + std::to_wstring(itemIndex) + L" exe=" + HolyInstalled::Leaf(path));
    {std::lock_guard<std::mutex> guard(g_processMutex);
     g_approvedLaunchTargets[static_cast<size_t>(itemIndex)]=std::move(approved);}
    if (sei.hProcess) TrackLaunchedProcess(itemIndex, path, sei.hProcess);
    return true;
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
static bool GetEnvironmentDirectory(const wchar_t* variable, std::wstring& out);
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
    out.clear(); DWORD type = 0, bytes = 0;
    if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
        !bytes || bytes > 65536 || bytes % sizeof(wchar_t) ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) return false;
    const DWORD capacity = bytes;
    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1, L'\0');
    if (RegQueryValueExW(key, valueName, nullptr, &type,
        reinterpret_cast<LPBYTE>(buffer.data()), &bytes) != ERROR_SUCCESS ||
        !bytes || bytes > capacity || bytes % sizeof(wchar_t) ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) return false;
    size_t chars = bytes / sizeof(wchar_t);
    while (chars && buffer[chars - 1] == L'\0') --chars;
    out.assign(buffer.data(), chars);
    if (out.find(L'\0') != std::wstring::npos) { out.clear(); return false; }
    out = TrimWhitespace(out);
    // Some publishers put %variables% in REG_SZ rather than REG_EXPAND_SZ.
    // Expand before splitting, then still apply absolute-path and trust checks.
    if (out.find(L'%') != std::wstring::npos) {
        const DWORD needed = ExpandEnvironmentStringsW(out.c_str(), nullptr, 0);
        if (needed <= 1 || needed > 32768) return false;
        std::vector<wchar_t> expanded(needed, L'\0');
        const DWORD actual = ExpandEnvironmentStringsW(out.c_str(), expanded.data(), needed);
        if (!actual || actual > needed) return false;
        out.assign(expanded.data());
        if (out.find(L'%') != std::wstring::npos) return false;
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
    std::wstring base;
    if (!GetEnvironmentDirectory(variable, base)) return;
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

    for (DWORD index = 0; !g_cancelRequested.load(); ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) break;

        HKEY item = nullptr;
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;

        std::wstring displayName;
        if ((ReadRegistryStringValue(item, L"DisplayName", displayName) &&
            SystemInformerDisplayName(displayName)) || HolyInstalled::SystemInformerKey(subName)) {
            std::wstring installLocation;
            if (ReadRegistryStringValue(item, L"InstallLocation", installLocation)) {
                installLocation = TrimWhitespace(installLocation);
                if (installLocation.size() >= 2 && installLocation.front() == L'"' && installLocation.back() == L'"')
                    installLocation = installLocation.substr(1, installLocation.size() - 2);
                if (!installLocation.empty()) {
                    AddSystemInformerCandidate(candidates, JoinPath(installLocation, L"SystemInformer.exe"));
                    AddSystemInformerCandidate(candidates, JoinPath(installLocation, L"System Informer.exe"));
                    for (const auto* relative : { L"amd64\\SystemInformer.exe", L"i386\\SystemInformer.exe", L"arm64\\SystemInformer.exe" })
                        AddSystemInformerCandidate(candidates,JoinPath(installLocation,relative));
                }
            }

            std::wstring displayIcon;
            if (ReadRegistryStringValue(item, L"DisplayIcon", displayIcon))
                AddSystemInformerCandidate(candidates, displayIcon);
            for (const auto* valueName : { L"UninstallString", L"QuietUninstallString" }) {
                std::wstring value, executable, args;
                if (!ReadRegistryStringValue(item, valueName, value)) continue;
                if (!HolyCommand::Split(value, executable, args)) continue;
                const auto parent = HolyInstalled::Parent(executable);
                if (parent.empty()) continue;
                for (const auto* relative : { L"SystemInformer.exe", L"amd64\\SystemInformer.exe", L"i386\\SystemInformer.exe", L"arm64\\SystemInformer.exe" })
                    AddSystemInformerCandidate(candidates, JoinPath(parent, relative));
            }
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
    for (DWORD index = 0; !found && !g_cancelRequested.load(); ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) break;

        HKEY item = nullptr;
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;

        std::wstring displayName;
        if ((ReadRegistryStringValue(item, L"DisplayName", displayName) &&
            SystemInformerDisplayName(displayName)) || HolyInstalled::SystemInformerKey(subName)) {
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

[[maybe_unused]] static bool FindSystemInformerUninstallCommand(std::wstring& command) {
    command.clear();
    return FindSystemInformerUninstallCommandInView(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_CURRENT_USER, KEY_WOW64_64KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_CURRENT_USER, KEY_WOW64_32KEY, command) ||
           FindSystemInformerUninstallCommandInView(HKEY_CURRENT_USER, 0, command);
}

static void SplitRegisteredCommand(const std::wstring& command,
                                   std::wstring& executable, std::wstring& arguments) {
    if (!HolyCommand::Split(command, executable, arguments)) {
        executable.clear(); arguments.clear();
    }
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
    return HolyInstalled::FtkDisplayName(TrimWhitespace(name));
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
    std::wstring base;
    if (!GetEnvironmentDirectory(variable, base)) return;
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

    for (DWORD index = 0; !g_cancelRequested.load(); ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) break;

        HKEY item = nullptr;
        if (RegOpenKeyExW(uninstall, subName, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;

        std::wstring displayName;
        if (ReadRegistryStringValue(item, L"DisplayName", displayName) &&
            displayMatcher && displayMatcher(displayName)) {
            std::wstring installLocation;
            if (ReadRegistryStringValue(item, L"InstallLocation", installLocation)) {
                installLocation = TrimWhitespace(installLocation);
                if (installLocation.size() >= 2 && installLocation.front() == L'"' && installLocation.back() == L'"')
                    installLocation = installLocation.substr(1, installLocation.size() - 2);
                for (const wchar_t* fileName : fileNames) {
                    if (fileName && *fileName)
                        AddInstalledProductCandidate(candidates, JoinPath(installLocation, fileName), executableMatcher);
                    if (fileName && *fileName && executableMatcher == LooksLikeFtkImagerExecutable)
                        for (const auto* child : { L"bin", L"x64", L"x86" })
                            AddInstalledProductCandidate(candidates, JoinPath(JoinPath(installLocation, child), fileName), executableMatcher);
                }
            }

            std::wstring displayIcon;
            if (ReadRegistryStringValue(item, L"DisplayIcon", displayIcon))
                AddInstalledProductCandidate(candidates, displayIcon, executableMatcher);
            // InstallLocation is often missing in MSI/bootstrapper registrations.
            // DisplayIcon/uninstaller parent can still locate the real app.
            for (const wchar_t* valueName : { L"DisplayIcon", L"UninstallString", L"QuietUninstallString" }) {
                std::wstring value, executable, args;
                if (!ReadRegistryStringValue(item, valueName, value)) continue;
                if (wcscmp(valueName, L"DisplayIcon") == 0) executable = RegistryPathToExecutable(value);
                else SplitRegisteredCommand(value, executable, args);
                const auto parent = HolyInstalled::Parent(executable);
                if (parent.empty()) continue;
                for (const auto* fileName : fileNames)
                    AddInstalledProductCandidate(candidates, JoinPath(parent, fileName), executableMatcher);
            }
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
    for (DWORD index = 0; !found && !g_cancelRequested.load(); ++index) {
        wchar_t subName[512]{};
        DWORD subNameLength = static_cast<DWORD>(ARRAYSIZE(subName));
        LONG status = RegEnumKeyExW(uninstall, index, subName, &subNameLength,
                                    nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) break;

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

[[maybe_unused]] static bool FindInstalledProductUninstallCommand(InstalledProductDisplayMatcher displayMatcher,
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

    for (const auto& path : candidates) { if (g_cancelRequested.load()) return {}; if (FileExists(path)) return path; }
    return {};
}

static std::wstring FindFtkExecutableUnderVendorDirectory(const std::wstring& directory,
                                                           int depthRemaining) {
    if (g_cancelRequested.load() || directory.empty() || depthRemaining < 0 || !DirectoryExists(directory)) return {};

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

    for (const auto& path : candidates) { if (g_cancelRequested.load()) return {}; if (FileExists(path)) return path; }

    // Some FTK Imager installers use a versioned subfolder and omit
    // InstallLocation/DisplayIcon. Search only the normal vendor directories,
    // with a small depth limit, instead of scanning Program Files globally.
    for (const wchar_t* variable : { L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)" }) {
        std::wstring base;
        if (!GetEnvironmentDirectory(variable, base)) continue;
        for (const wchar_t* vendor : { L"AccessData", L"Exterro", L"FTK Imager" }) {
            const std::wstring found = FindFtkExecutableUnderVendorDirectory(JoinPath(base, vendor), 3);
            if (!found.empty()) return found;
        }
    }
    return {};
}

static bool IsProcessHackerItemIndex(int index) {
    return index >= 0 && static_cast<size_t>(index) < kItemCount && LowerAscii(kItems[index].name) == L"processhacker";
}
static bool ProcessHackerDisplayName(const std::wstring& input) {
    const auto name = LowerAscii(TrimWhitespace(input));
    return name == L"process hacker" || name.rfind(L"process hacker ", 0) == 0;
}
static bool LooksLikeProcessHackerExecutable(const std::wstring& path) {
    return LowerAscii(FileNameOnly(path)) == L"processhacker.exe";
}
static std::wstring FindInstalledProcessHackerPath() {
    std::vector<std::wstring> candidates;
    for (auto root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER })
        for (REGSAM view : { REGSAM(KEY_WOW64_64KEY), REGSAM(KEY_WOW64_32KEY) }) {
            AddInstalledAppPathCandidate(candidates, root, view, L"ProcessHacker.exe", LooksLikeProcessHackerExecutable);
            AddInstalledUninstallCandidates(candidates, root, view, ProcessHackerDisplayName,
                LooksLikeProcessHackerExecutable, { L"ProcessHacker.exe", L"x64\\ProcessHacker.exe", L"x86\\ProcessHacker.exe" });
        }
    for (const auto* variable : { L"ProgramW6432", L"ProgramFiles", L"ProgramFiles(x86)", L"LOCALAPPDATA" })
        for (const auto* relative : { L"Process Hacker 2\\ProcessHacker.exe", L"Process Hacker\\ProcessHacker.exe",
                                     L"Programs\\Process Hacker 2\\ProcessHacker.exe" })
            AddInstalledEnvironmentCandidate(candidates, variable, relative, LooksLikeProcessHackerExecutable);
    for (const auto& path : candidates) { if (g_cancelRequested.load()) return {}; if (FileExists(path)) return path; }
    return {};
}

static bool IsPathUnderDirectory(const std::wstring& path, const std::wstring& base) {
    if (path.empty() || base.empty() || path.size() < base.size()) return false;
    if (_wcsnicmp(path.c_str(), base.c_str(), base.size()) != 0) return false;
    if (path.size() == base.size()) return true;
    const wchar_t next = path[base.size()];
    return next == L'\\' || next == L'/';
}

static bool GetEnvironmentDirectory(const wchar_t* variable, std::wstring& out) {
    // Installation roots are OS known folders, never caller-controlled env vars.
    const KNOWNFOLDERID* id = nullptr;
    if (wcscmp(variable, L"ProgramW6432") == 0) id = &FOLDERID_ProgramFilesX64;
    else if (wcscmp(variable, L"ProgramFiles") == 0) id = &FOLDERID_ProgramFiles;
    else if (wcscmp(variable, L"ProgramFiles(x86)") == 0) id = &FOLDERID_ProgramFilesX86;
    else if (wcscmp(variable, L"LOCALAPPDATA") == 0) id = &FOLDERID_LocalAppData;
    else if (wcscmp(variable, L"ProgramData") == 0) id = &FOLDERID_ProgramData;
    out.clear();
    if (!id) return false;
    PWSTR path = nullptr;
    if (FAILED(SHGetKnownFolderPath(*id, 0, nullptr, &path)) || !path) {
        if (path) CoTaskMemFree(path);
        if (wcscmp(variable, L"ProgramW6432") != 0) return false;
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
        const bool ok = ReadRegistryStringValue(key, L"ProgramFilesDir", out);
        RegCloseKey(key); return ok;
    }
    out = path;
    CoTaskMemFree(path);
    return !out.empty();
}

static bool IsTrustedUninstallerPath(std::wstring& executable, std::wstring* diagnostic, bool enforceKnownRoot) {
    auto fail = [&](const wchar_t* reason) { if (diagnostic) *diagnostic = reason; return false; };
    executable = TrimWhitespace(executable);
    if (executable.empty()) return fail(L"Пустой путь или ошибочные кавычки в записи удаления.");
    if (executable.find(L'%') != std::wstring::npos)
        return fail(L"Не удалось раскрыть переменную окружения в записи удаления.");
    const auto fileName = LowerAscii(FileNameOnly(executable));
    for (const auto* forbidden : { L"cmd.exe", L"powershell.exe", L"pwsh.exe", L"wscript.exe",
        L"cscript.exe", L"mshta.exe", L"rundll32.exe", L"regsvr32.exe" })
        if (fileName == forbidden) return fail(L"Запуск командного интерпретатора из реестра запрещён.");
    if (fileName == L"msiexec.exe" || fileName == L"msiexec") {
        wchar_t systemDir[MAX_PATH]{};
        const UINT n = GetSystemDirectoryW(systemDir, ARRAYSIZE(systemDir));
        if (!n || n >= ARRAYSIZE(systemDir)) return fail(L"Недоступен системный Windows Installer.");
        const auto trusted = JoinPath(systemDir, L"msiexec.exe");
        // Bare msiexec is resolved ourselves, never through PATH. A supplied
        // absolute lookalike is rejected rather than silently substituted.
        if (executable.find_first_of(L"\\/:") != std::wstring::npos &&
            _wcsicmp(executable.c_str(), trusted.c_str()) != 0)
            return fail(L"Путь msiexec не совпадает с системным Windows Installer.");
        executable = trusted;
    } else {
        if (!EndsWithI(executable, L".exe") || executable.size() < 3 ||
            executable[1] != L':' || executable[2] != L'\\')
            return fail(L"Требуется абсолютный локальный путь к EXE; UNC и относительные пути запрещены.");
        wchar_t fullBuffer[32768]{};
        const DWORD n = GetFullPathNameW(executable.c_str(), ARRAYSIZE(fullBuffer), fullBuffer, nullptr);
        if (!n || n >= ARRAYSIZE(fullBuffer)) return fail(L"Не удалось нормализовать путь деинсталлятора.");
        const std::wstring full(fullBuffer, n);
        std::wstring pf64, pf, pf86, local, data;
        GetEnvironmentDirectory(L"ProgramW6432", pf64); GetEnvironmentDirectory(L"ProgramFiles", pf);
        GetEnvironmentDirectory(L"ProgramFiles(x86)", pf86); GetEnvironmentDirectory(L"LOCALAPPDATA", local);
        GetEnvironmentDirectory(L"ProgramData", data);
        if (enforceKnownRoot && !IsPathUnderDirectory(full, pf64) && !IsPathUnderDirectory(full, pf) &&
            !IsPathUnderDirectory(full, pf86) &&
            !IsPathUnderDirectory(full, local.empty() ? L"" : JoinPath(local, L"Programs")) &&
            !IsPathUnderDirectory(full, data.empty() ? L"" : JoinPath(data, L"Package Cache")))
            return fail(L"Каталог установки не входит в разрешённые корни. Используйте Параметры Windows → Приложения либо восстановите установку из проверенного пакета.");
        executable = full;
    }
    const DWORD attributes = GetFileAttributesW(executable.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        if (diagnostic) *diagnostic = GetLastError() == ERROR_ACCESS_DENIED
            ? L"Отказ в доступе к EXE деинсталлятора. Проверьте права установки."
            : L"EXE деинсталлятора отсутствует. Восстановите установку из проверенного пакета.";
        return false;
    }
    HandleSet locks;
    if (!LockRegularFile(executable, locks)) {
        if (diagnostic) *diagnostic = GetLastError() == ERROR_ACCESS_DENIED
            ? L"Отказ в доступе при защите файла деинсталлятора."
            : L"Путь содержит запрещённый компонент/reparse point либо файл занят для записи.";
        return false;
    }
    return true;
}

static void CollectRegisteredUninstallCommands(InstalledProductDisplayMatcher matcher,
                                               std::vector<std::wstring>& commands) {
    commands.clear();
    for (const auto root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
        for (const REGSAM view : { REGSAM(KEY_WOW64_64KEY), REGSAM(KEY_WOW64_32KEY) }) {
            HKEY uninstall = nullptr;
            const LONG opened = RegOpenKeyExW(root,L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",0,KEY_READ|view,&uninstall);
            FullLog(L"ARP root=" + std::wstring(root==HKEY_LOCAL_MACHINE?L"HKLM":L"HKCU") + L" view=" + std::to_wstring(view) + L" open=" + std::to_wstring(opened));
            if (opened != ERROR_SUCCESS) continue;
            for (DWORD index = 0; !g_cancelRequested.load(); ++index) {
                wchar_t name[512]{}; DWORD chars = ARRAYSIZE(name);
                const LONG enumerated=RegEnumKeyExW(uninstall,index,name,&chars,nullptr,nullptr,nullptr,nullptr);
                if (enumerated!=ERROR_SUCCESS) { if (enumerated!=ERROR_NO_MORE_ITEMS) FullLog(L"ARP enumerate error="+std::to_wstring(enumerated)); break; }
                HKEY item = nullptr;
                if (RegOpenKeyExW(uninstall, name, 0, KEY_READ | view, &item) != ERROR_SUCCESS) continue;
                std::wstring display;
                if ((ReadRegistryStringValue(item, L"DisplayName", display) && matcher(display)) ||
                    (matcher == SystemInformerDisplayName && HolyInstalled::SystemInformerKey(name))) {
                    DWORD msi = 0;
                    if (ReadRegistryDwordValue(item, L"WindowsInstaller", msi) && msi && LooksLikeMsiProductCode(name))
                        commands.push_back(L"msiexec.exe /X" + std::wstring(name) + L" /qn /norestart");
                    else for (const auto* field : { L"UninstallString", L"QuietUninstallString" }) {
                        std::wstring command;
                        DWORD type=0, bytes=0;
                        const LONG queried=RegQueryValueExW(item,field,nullptr,&type,nullptr,&bytes);
                        const bool read=ReadRegistryStringValue(item,field,command);
                        // Never record raw registry commands (may contain private data).
                        FullLog(std::wstring(L"ARP match field=") + field + L" status=" + std::to_wstring(queried) +
                            L" type=" + std::to_wstring(type) + L" bytes=" + std::to_wstring(bytes) + L" parsed=" + std::to_wstring(read));
                        if (read && std::find(commands.begin(),commands.end(),command)==commands.end()) commands.push_back(command);
                    }
                }
                RegCloseKey(item);
            }
            RegCloseKey(uninstall);
        }
    }
}

static bool HasRegisteredProduct(InstalledProductDisplayMatcher matcher, bool& readable) {
    readable = true; bool found = false;
    if (g_cancelRequested.load()) { readable = false; return false; }
    for (const auto root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
        for (const REGSAM view : { REGSAM(KEY_WOW64_64KEY), REGSAM(KEY_WOW64_32KEY) }) {
            HKEY uninstall = nullptr;
            const LONG opened = RegOpenKeyExW(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                0, KEY_READ | view, &uninstall);
            if (opened == ERROR_FILE_NOT_FOUND) continue;
            if (opened != ERROR_SUCCESS) { readable = false; continue; }
            for (DWORD i = 0;; ++i) {
                if (g_cancelRequested.load()) { RegCloseKey(uninstall); readable = false; return found; }
                wchar_t name[512]{}; DWORD n = ARRAYSIZE(name);
                const LONG status = RegEnumKeyExW(uninstall, i, name, &n, nullptr, nullptr, nullptr, nullptr);
                if (status == ERROR_NO_MORE_ITEMS) break;
                if (status != ERROR_SUCCESS) { readable = false; break; }
                HKEY item = nullptr;
                if (RegOpenKeyExW(uninstall, name, 0, KEY_READ | view, &item) != ERROR_SUCCESS) { readable = false; continue; }
                std::wstring display;
                if ((ReadRegistryStringValue(item, L"DisplayName", display) && matcher(display)) ||
                    (matcher == SystemInformerDisplayName && HolyInstalled::SystemInformerKey(name))) found = true;
                RegCloseKey(item);
            }
            RegCloseKey(uninstall);
        }
    }
    return found;
}

// Before invoking a possibly elevation-capable registry target, ensure an
// ordinary token cannot rewrite the target or replace it via its parent.
static bool IsWriteProtectedForOrdinaryUser(const std::wstring& path) {
    HandleSet handles;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)) return false;
    handles.Add(token);
    BYTE adminBuffer[SECURITY_MAX_SID_SIZE]{}; DWORD adminBytes = sizeof(adminBuffer);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminBuffer, &adminBytes)) return false;
    SID_AND_ATTRIBUTES disable{adminBuffer, 0}; HANDLE restricted = nullptr;
    if (!CreateRestrictedToken(token, DISABLE_MAX_PRIVILEGE, 1, &disable, 0, nullptr, 0, nullptr, &restricted)) return false;
    handles.Add(restricted);
    HANDLE impersonation = nullptr;
    if (!DuplicateToken(restricted, SecurityImpersonation, &impersonation)) return false;
    handles.Add(impersonation);
    PSECURITY_DESCRIPTOR security = nullptr;
    const DWORD status = GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        nullptr, nullptr, nullptr, nullptr, &security);
    if (status != ERROR_SUCCESS || !security) return false;
    GENERIC_MAPPING mapping{FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    DWORD privilegeBytes = 4096, granted = 0; BOOL access = FALSE;
    std::vector<BYTE> privileges(privilegeBytes);
    const BOOL checked = AccessCheck(security, impersonation, MAXIMUM_ALLOWED, &mapping,
        reinterpret_cast<PRIVILEGE_SET*>(privileges.data()), &privilegeBytes, &granted, &access);
    LocalFree(security);
    const DWORD mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER;
    return checked && access && !(granted & mutation);
}

// Custom install directories are not intrinsically untrusted. Authenticate
// the actual executable instead of treating a Program Files prefix as proof.
static bool VerifiedSignerSpki(const std::wstring& path, std::wstring& spkiHash, std::wstring& error) {
    spkiHash.clear();
    HandleSet locks;
    if (!LockRegularFile(path, locks)) { error = L"Файл подписи недоступен или небезопасен."; return false; }
    WINTRUST_FILE_INFO file{}; file.cbStruct = sizeof(file); file.pcwszFilePath = path.c_str();
    WINTRUST_DATA trust{}; trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    struct TrustScope {
        GUID& action; WINTRUST_DATA& data;
        ~TrustScope() { data.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(nullptr, &action, &data); }
    } scope{action, trust};
    const LONG status = WinVerifyTrust(nullptr, &action, &trust);
    if (status != ERROR_SUCCESS) {
        error = L"Authenticode/цепочка доверия/проверка отзыва не подтверждены (код " +
                std::to_wstring(static_cast<unsigned long>(status)) + L").";
        return false;
    }
    auto* provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
    auto* signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
    if (!signer || !signer->csCertChain || !signer->pasCertChain || !signer->pasCertChain[0].pCert) {
        error = L"Не получен сертификат подписанта."; return false;
    }
    BYTE* encoded = nullptr; DWORD encodedBytes = 0;
    struct LocalScope { BYTE*& value; ~LocalScope() { if (value) LocalFree(value); } } local{encoded};
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        &signer->pasCertChain[0].pCert->pCertInfo->SubjectPublicKeyInfo,
        CRYPT_ENCODE_ALLOC_FLAG, nullptr, &encoded, &encodedBytes) ||
        !HashBytes(encoded, encodedBytes, spkiHash)) {
        error = L"Не удалось проверить ключ издателя."; return false;
    }
    return true;
}

static int InstalledProductIndex(const wchar_t* label) {
    for (int i = 0; i < static_cast<int>(kItemCount); ++i) {
        if ((std::wstring(label) == L"System Informer" && IsSystemInformerItemIndex(i)) ||
            (std::wstring(label) == L"Recuva" && IsRecuvaItemIndex(i)) ||
            (std::wstring(label) == L"FTK Imager" && IsFtkImagerItemIndex(i)) ||
            (std::wstring(label) == L"Process Hacker" && IsProcessHackerItemIndex(i))) return i;
    }
    return -1;
}
static bool IsExactPinnedInstaller(int itemIndex, const std::wstring& target) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount || !EndsWithI(kItems[itemIndex].file, L".exe")) return false;
    HandleSet locks; std::wstring unused;
    return LockRegularFile(target, locks) && VerifyPinnedPayloadForItem(itemIndex, target, unused);
}
static bool MatchesPinnedInstallerPublisher(int itemIndex, const std::wstring& target, std::wstring& error) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount || !EndsWithI(kItems[itemIndex].file, L".exe")) {
        error = L"Нет прямого закреплённого EXE-установщика для подтверждения издателя."; return false;
    }
    const auto anchor = ItemPath(itemIndex);
    HandleSet anchorLocks;
    if (!LockRegularFile(anchor, anchorLocks) || !VerifyPinnedPayloadForItem(itemIndex, anchor, error)) {
        error = L"Для проверки нестандартной установки нужен исходный EXE-установщик с закреплённым SHA-256 в Downloads HolyCheck.";
        return false;
    }
    std::wstring expectedSigner, actualSigner;
    if (!VerifiedSignerSpki(anchor, expectedSigner, error) || !VerifiedSignerSpki(target, actualSigner, error)) return false;
    if (actualSigner != expectedSigner) { error = L"Ключ издателя не совпадает с ключом доверенного установщика."; return false; }
    return true;
}
static bool VerifyInstalledProgramTrust(int itemIndex, const std::wstring& path, std::wstring& error) {
    std::wstring installed;
    if (IsSystemInformerItemIndex(itemIndex)) installed = FindInstalledSystemInformerPath();
    else if (IsRecuvaItemIndex(itemIndex)) installed = FindInstalledRecuvaPath();
    else if (IsFtkImagerItemIndex(itemIndex)) installed = FindInstalledFtkImagerPath();
    else if (IsProcessHackerItemIndex(itemIndex)) installed = FindInstalledProcessHackerPath();
    std::wstring canonical = path, registered = installed;
    if (installed.empty() || !IsTrustedUninstallerPath(canonical, &error, false) ||
        !IsTrustedUninstallerPath(registered, &error, false) || _wcsicmp(canonical.c_str(), registered.c_str()) != 0) {
        if (error.empty()) error = L"Путь не соответствует обнаруженной установленной программе.";
        return false;
    }
    // Preserve the existing known-root policy for ordinary installed-app
    // launching; custom roots need a stronger file identity/ACL proof.
    std::wstring known = canonical;
    if (IsTrustedUninstallerPath(known)) return true;
    const auto parent = canonical.substr(0, canonical.find_last_of(L'\\'));
    if (IsWriteProtectedForOrdinaryUser(canonical) && IsWriteProtectedForOrdinaryUser(parent)) return true;
    if (IsExactPinnedInstaller(itemIndex, canonical) || MatchesPinnedInstallerPublisher(itemIndex, canonical, error)) return true;
    error = L"Не подтверждена подлинность приложения в нестандартном каталоге. " + error;
    return false;
}

static bool ValidateVendorUninstallArguments(const std::wstring& arguments) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW((L"uninstall.exe " + arguments).c_str(), &argc);
    if (!argv) return false;
    bool ok = true;
    for (int i = 1; ok && i < argc; ++i) {
        const auto arg = LowerAscii(argv[i]);
        // No file paths, URLs, scripts, transforms or arbitrary option values.
        ok = arg == L"/s" || arg == L"/silent" || arg == L"/verysilent" ||
             arg == L"/suppressmsgboxes" || arg == L"/norestart" || arg == L"/uninstall" ||
             arg == L"-uninstall" || arg == L"-silent" || arg == L"/quiet";
    }
    LocalFree(argv); return ok;
}

// Historical name retained for source compatibility. The wait is now on the
// worker, not on the UI, and success means a completed successful process.
static bool LaunchRegisteredCommandNoWait(const wchar_t* displayLabel,
                                          const std::wstring& command,
                                          const std::wstring& installedPath,
                                          bool& started, std::wstring& error) {
    started = false; error.clear();
    std::wstring executable, arguments;
    SplitRegisteredCommand(command, executable, arguments);
    if (!IsTrustedUninstallerPath(executable, &error, false)) {
        error = std::wstring(displayLabel) + L": запись удаления заблокирована. " + error;
        return false;
    }
    const auto exeName = LowerAscii(FileNameOnly(executable));
    const bool msi = exeName == L"msiexec.exe";
    bool machineMsi = false;
    if (msi) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW((L"msiexec.exe " + arguments).c_str(), &argc);
        std::wstring product; bool valid = argv != nullptr;
        for (int i = 1; valid && i < argc; ++i) {
            const std::wstring arg = argv[i], lower = LowerAscii(arg);
            if (lower == L"/qn" || lower == L"/qf" || lower == L"/quiet" || lower == L"/norestart") continue;
            if (!product.empty() || arg.size() < 2 || (arg[0] != L'/' && arg[0] != L'-') ||
                (lower[1] != L'x' && lower[1] != L'i')) { valid = false; break; }
            product = arg.substr(2);
            if (product.empty() && i + 1 < argc) product = argv[++i];
            valid = LooksLikeMsiProductCode(product);
        }
        if (argv) LocalFree(argv);
        if (!valid || product.empty()) { error = L"Небезопасные параметры MSI заблокированы."; return false; }
        InstalledProductDisplayMatcher matcher = nullptr;
        if (std::wstring(displayLabel) == L"System Informer") matcher = SystemInformerDisplayName;
        else if (std::wstring(displayLabel) == L"Recuva") matcher = RecuvaDisplayName;
        else if (std::wstring(displayLabel) == L"FTK Imager") matcher = FtkImagerDisplayName;
        else if (std::wstring(displayLabel) == L"Process Hacker") matcher = ProcessHackerDisplayName;
        if (!matcher) { error = L"Неизвестный продукт MSI."; return false; }
        bool confirmed = false, otherProduct = false; unsigned queryError = ERROR_UNKNOWN_PRODUCT;
        // Only the machine and CURRENT user's installed instances. No trust
        // in DisplayName from the writable ARP key, no arbitrary other SID.
        for (const auto context : { MSIINSTALLCONTEXT_MACHINE, MSIINSTALLCONTEXT_USERMANAGED,
                                    MSIINSTALLCONTEXT_USERUNMANAGED }) {
            std::wstring name;
            const bool readName = HolyUninstall::ReadMsiText([&](wchar_t* out, uint32_t& count) {
                DWORD n = count;
                const UINT code = MsiGetProductInfoExW(product.c_str(), nullptr, context,
                    INSTALLPROPERTY_INSTALLEDPRODUCTNAME, out, &n);
                count = n; return static_cast<unsigned>(code);
            }, name, queryError);
            FullLog(L"MSI installed identity context=" + std::to_wstring(static_cast<unsigned>(context)) +
                L" status=" + std::to_wstring(queryError) + L" read=" + std::to_wstring(readName) + L" matches=" + std::to_wstring(readName && matcher(name)));
            if (readName && matcher(name)) { confirmed = true; machineMsi = context == MSIINSTALLCONTEXT_MACHINE; break; }
            if (readName) otherProduct = true;
        }
        if (!confirmed) {
            if (otherProduct) { error = L"GUID MSI относится не к выбранной программе. Удаление заблокировано."; return false; }
            error = L"Windows Installer не подтвердил установленный целевой продукт в контексте компьютера/текущего пользователя (код " +
                    std::to_wstring(queryError) + L"). Запись MSI может быть устаревшей; восстановите установку штатным пакетом.";
            return false;
        }
        arguments = L"/X" + product + L" /qf /norestart"; // Full vendor UI; preserve UAC and user control.
    } else {
        // A registry DisplayName alone cannot authorise an arbitrary EXE.
        std::wstring trustedInstalled = installedPath;
        if (!IsTrustedUninstallerPath(trustedInstalled, &error, false)) {
            error = L"Не подтверждён каталог установленной программы. Используйте восстановление установки или Параметры Windows → Приложения.";
            return false;
        }
        const bool sameExe = _wcsicmp(executable.c_str(), trustedInstalled.c_str()) == 0;
        const bool pinnedSetup = IsExactPinnedInstaller(InstalledProductIndex(displayLabel), executable);
        const bool explicitUninstall = LowerAscii(arguments).find(L"uninstall") != std::wstring::npos;
        // A cached/custom-location copy of the EXACT pinned setup may be used
        // in explicit uninstall mode, even when it is not beside the main EXE.
        if (!pinnedSetup && !HolyInstalled::BoundUninstaller(displayLabel, executable, trustedInstalled)) {
            error = L"Деинсталлятор не соответствует программе (EXE: "+ exeName + L"). Нужна штатная запись удаления или восстановление проверенного установщика.";
            return false;
        }
        if (!ValidateVendorUninstallArguments(arguments) ||
            ((sameExe || pinnedSetup || exeName == L"systeminformer-setup.exe") && !explicitUninstall)) {
            error = L"Неизвестные или небезопасные аргументы деинсталлятора. Используйте штатное удаление в Windows.";
            return false;
        }
    }
    // Only the validated System Informer setup uses this protocol. Remove quiet
    // flags for this product so its real uninstall wizard is visible. Do not
    // guess flags for arbitrary vendor EXEs or main application binaries.
    if (!msi && std::wstring(displayLabel) == L"System Informer" &&
        (exeName == L"systeminformer-setup.exe" || IsExactPinnedInstaller(InstalledProductIndex(displayLabel), executable)))
        arguments = HolyUninstall::SystemInformerArguments();
    if(!msi) {
        int count=0;LPWSTR* argv=CommandLineToArgvW((L"vendor.exe "+arguments).c_str(),&count);
        if(!argv){error=L"Не удалось подготовить видимое окно удаления.";return false;}
        std::vector<std::wstring> tokens;
        for(int i=1;i<count;++i)tokens.emplace_back(argv[i]);
        LocalFree(argv);
        if(!HolyUninstall::InteractiveVendorArguments(tokens,arguments)) {
            error=L"Неподдерживаемые параметры окна удаления.";return false;
        }
    }
    FullLog(std::wstring(L"UNINSTALL validated arguments product=") + displayLabel +
        L" exe=" + exeName + L" visibleSI=" + std::to_wstring(!msi && std::wstring(displayLabel)==L"System Informer") + L" MSI=" + std::to_wstring(msi) + L" machine=" + std::to_wstring(machineMsi));
    HandleSet locks;
    if (!LockRegularFile(executable, locks)) {
        error = L"Не удалось защитить EXE деинсталлятора от подмены."; return false;
    }
    if (!IsValidPeExecutable(executable, &error)) return false;
    if (!msi && std::wstring(displayLabel)==L"System Informer" &&
        _wcsicmp(executable.c_str(),ItemPath(InstalledProductIndex(displayLabel)).c_str())==0) {
        const int item=InstalledProductIndex(displayLabel);
        std::map<std::wstring,std::wstring> expected;
        std::set<std::wstring> payloads;
        if(item<0 || !CollectTabExpected(kItems[item].tab,locks,expected,payloads,error) ||
            !CheckExtractedInventory(ItemDirectory(item),expected,payloads,locks,error)) {
            FullLog(L"UNINSTALL SI external namespace rejected: "+error);return false;
        }
    }
    const auto parentPath = executable.substr(0, executable.find_last_of(L'\\'));
    if (!msi && (!IsWriteProtectedForOrdinaryUser(executable) || !IsWriteProtectedForOrdinaryUser(parentPath))) {
        // A writable custom install is accepted only when the real signature,
        // chain/revocation and exact signer key match a SHA-pinned installer.
        if (!IsExactPinnedInstaller(InstalledProductIndex(displayLabel), executable) &&
            !MatchesPinnedInstallerPublisher(InstalledProductIndex(displayLabel), executable, error)) {
            error = std::wstring(displayLabel) + L": пользовательский каталог; подлинность деинсталлятора не подтверждена. " +
                    error + L" Штатное удаление доступно в Параметрах Windows → Приложения.";
            return false;
        }
    }
    SHELLEXECUTEINFOW sei{}; sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
    sei.hwnd = g_mainWindow; sei.lpVerb = machineMsi ? L"runas" : L"open"; sei.lpFile = executable.c_str();
    sei.lpParameters = arguments.empty() ? nullptr : arguments.c_str();
    sei.lpDirectory = parentPath.c_str(); sei.nShow = SW_SHOWNORMAL;
    if (g_cancelRequested.load()) { error = L"Удаление отменено до запуска."; return false; }
    // A cancelled UAC or a failed launch is terminal: don't fall back to a
    // second registry command and prompt/execute again.
    started = true;
    if (g_cancelRequested.load()) { error = L"Операция отменена до запуска."; return false; }
    FullLog(std::wstring(L"UNINSTALL launch product=") + displayLabel + L" exe=" + exeName + L" verb=" + sei.lpVerb);
    if (!ShellExecuteExW(&sei)) {
        DWORD code = GetLastError();
        FullLog(L"UNINSTALL ShellExecute error=" + std::to_wstring(code));
        if (code == ERROR_ELEVATION_REQUIRED) {
            if (g_cancelRequested.load()) { error = L"Удаление отменено до UAC."; return false; }
            sei.lpVerb = L"runas"; // Native UAC, only for an already validated target.
            if (!ShellExecuteExW(&sei)) code = GetLastError(); else code = ERROR_SUCCESS;
        }
        if (code != ERROR_SUCCESS) {
            error = code == ERROR_CANCELLED ? L"Пользователь отменил запрос UAC/запуск деинсталлятора."
                : L"Ошибка запуска деинсталлятора: " + Win32ErrorText(code);
            return false;
        }
    }
    if (!sei.hProcess) { error = L"Windows не вернула процесс. Завершение удаления не подтверждено."; return false; }
    // Do not retain the target read lock while it tries to remove itself.
    for (HANDLE h : locks.handles) CloseHandle(h); locks.handles.clear();
    HandleSet process; process.Add(sei.hProcess);
    const auto deadline = GetTickCount64() + 30ULL * 60 * 1000;
    for (;;) {
        const DWORD wait = WaitForSingleObject(sei.hProcess, 100);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED) { error = L"Не удалось получить состояние деинсталлятора."; return false; }
        if (g_cancelRequested.load() || GetTickCount64() >= deadline) {
            error = L"Ожидание удаления отменено/истекло. Деинсталлятор может продолжать работу; удаление не подтверждено.";
            return false;
        }
    }
    DWORD code = 0;
    const bool gotExit = GetExitCodeProcess(sei.hProcess, &code) != FALSE;
    FullLog(std::wstring(L"UNINSTALL process exited product=") + displayLabel + L" gotCode=" + std::to_wstring(gotExit) + L" code=" + std::to_wstring(code));
    if (!gotExit ||
        (code != 0 && !(msi && (code == 3010 || code == 1641)))) {
        error = L"Деинсталлятор завершился с ошибкой (код " + std::to_wstring(code) + L").";
        return false;
    }
    if (msi && (code == 3010 || code == 1641)) {
        error = L"Windows Installer запросил перезагрузку (код " + std::to_wstring(code) +
                L"). Удаление до перезагрузки не объявляется завершённым; файлы HolyCheck сохранены.";
        return false;
    }
    return true;
}

static void SetCleanupWaiting(bool waiting) {
    g_cleanupWaiting.store(waiting); PostMessageW(g_mainWindow, WM_APP_UNINSTALL_STATUS, 0, 0);
}
static void SetUninstallStatus(int index, bool waiting) {
    g_uninstallWaiting.store(waiting); g_uninstallItem.store(index);
    // Status must repaint once even when vendor UI owns focus and the
    // animation timer is paused. No log entry and no cross-thread drawing.
    PostMessageW(g_mainWindow, WM_APP_UNINSTALL_STATUS, 0, 0);
}
// Recovery is deliberately limited to the exact standard target requested by
// the user. The pinned 32-bit vendor setup defaults to this directory without
// an ARP InstallLocation. Do not guess a directory flag or edit registry state.
static bool ValidateSiRecoveryTarget(const std::wstring& installed,std::wstring& error) {
    const auto root=HolyInstalled::SystemInformerInstallRoot(installed);
    if(!HolyInstalled::StandardSystemInformerLocation(installed)) {
        error=L"Без записи удаления восстановительный setup разрешён только для C:\\Program Files\\SystemInformer. Для другого пути требуется штатная запись/восстановление установки.";return false;
    }
    HandleSet locks;
    if(!LockRegularFile(installed,locks)||!IsValidPeExecutable(installed,&error)||
        !IsWriteProtectedForOrdinaryUser(installed)||!IsWriteProtectedForOrdinaryUser(root)) {
        if(error.empty())error=L"Не подтверждены файл и права стандартной установки System Informer.";return false;
    }
    for(const auto* name:{L"SystemInformer",L"SystemInformer-Preview",L"SystemInformer-Canary",L"SystemInformer-Developer"}) {
        HKEY key=nullptr;const auto path=std::wstring(L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\")+name;
        const LONG opened=RegOpenKeyExW(HKEY_LOCAL_MACHINE,path.c_str(),0,KEY_READ|KEY_WOW64_64KEY,&key);
        if(opened==ERROR_FILE_NOT_FOUND)continue;
        if(opened!=ERROR_SUCCESS){error=L"Не удалось исключить другую InstallLocation System Informer (код "+std::to_wstring(opened)+L").";return false;}
        DWORD type=0,bytes=0;const LONG status=RegQueryValueExW(key,L"InstallLocation",nullptr,&type,nullptr,&bytes);
        std::wstring value;const bool read=ReadRegistryStringValue(key,L"InstallLocation",value);
        bool expansion=false;
        if(status==ERROR_SUCCESS && bytes<=65536 && bytes%sizeof(wchar_t)==0) {
            std::vector<wchar_t> raw(bytes/sizeof(wchar_t)+1,L'\0');DWORD count=bytes;
            if(RegQueryValueExW(key,L"InstallLocation",nullptr,&type,reinterpret_cast<BYTE*>(raw.data()),&count)!=ERROR_SUCCESS) expansion=true;
            else expansion=std::find(raw.begin(),raw.end(),L'%')!=raw.end();
        }
        RegCloseKey(key);
        if(status==ERROR_FILE_NOT_FOUND||(status==ERROR_SUCCESS&&(type==REG_SZ||type==REG_EXPAND_SZ)&&bytes<=2))continue;
        while(!value.empty()&&value.back()==L'\\')value.pop_back();
        // Vendor reads this field itself: reject expansions/aliases and any
        // differing registered target rather than uninstall a different tree.
        if(!read||expansion||LowerAscii(value)!=LowerAscii(root)) {error=L"InstallLocation System Informer не совпадает с подтверждённым стандартным каталогом. Восстановительное удаление заблокировано.";return false;}
    }
    // The vendor can recurse over its install tree. Refuse recovery if a link
    // could redirect it outside the declared directory; no traversal of links.
    unsigned seen=0;
    std::function<bool(const std::wstring&,unsigned)> check=[&](const std::wstring& dir,unsigned depth) {
        if(depth>16||seen>20000||g_cancelRequested.load())return false;
        HandleSet directories;if(!LockDirectoryChain(dir,directories))return false;
        WIN32_FIND_DATAW data{};HANDLE find=FindFirstFileW(JoinPath(dir,L"*").c_str(),&data);
        if(find==INVALID_HANDLE_VALUE)return GetLastError()==ERROR_FILE_NOT_FOUND;
        bool ok=true;
        do {
            if(!wcscmp(data.cFileName,L".")||!wcscmp(data.cFileName,L".."))continue;
            if(++seen>20000||g_cancelRequested.load()||(data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)){ok=false;break;}
            if((data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&!check(JoinPath(dir,data.cFileName),depth+1)){ok=false;break;}
        } while(FindNextFileW(find,&data));
        if(ok&&GetLastError()!=ERROR_NO_MORE_FILES)ok=false;FindClose(find);return ok;
    };
    if(!check(root,0)){error=L"Дерево System Informer недоступно, содержит ссылку/reparse point либо проверка отменена. Setup не запущен.";return false;}
    return true;
}
static bool PrepareSiRecoveryCommand(const std::wstring& installed,std::wstring& command,std::wstring& error) {
    if(!ValidateSiRecoveryTarget(installed,error))return false;
    const int item=InstalledProductIndex(L"System Informer");if(item<0)return false;
    std::unique_lock<std::recursive_mutex> guard(g_tabFileMutex[kItems[item].tab]);
    if(!EnsureTabDirectories()){error=L"Недоступна папка для проверенного setup System Informer.";return false;}
    const auto setup=ItemPath(item);
    if(FileExists(setup)) {
        if(!IsExactPinnedInstaller(item,setup)){error=L"Имеющийся setup System Informer не совпадает с доверенным SHA-256. Файл сохранён; восстановительное удаление не запущено.";return false;}
    } else {
        FullLog(L"UNINSTALL SI recovery: fetching exact SHA-pinned vendor setup for C:\\Program Files\\SystemInformer");
        if(!DownloadHttpsFile(item,kItems[item].url,setup,kItems[item].file,error))return false;
    }
    // Recheck the target after the network wait, before authorising execution.
    if(!ValidateSiRecoveryTarget(installed,error)||!IsExactPinnedInstaller(item,setup))return false;
    command=L"\""+setup+L"\" "+HolyUninstall::SystemInformerArguments();return true;
}
static bool LaunchRegisteredProductUninstallerNoWait(const wchar_t* label,
        InstalledProductDisplayMatcher matcher, const std::wstring& installed, std::wstring& error) {
    struct StatusScope {
        explicit StatusScope(const wchar_t* label) { SetUninstallStatus(InstalledProductIndex(label), false); }
        ~StatusScope() { SetUninstallStatus(-1, false); }
    } status(label);
    std::vector<std::wstring> commands;
    CollectRegisteredUninstallCommands(matcher, commands);
    FullLog(std::wstring(L"UNINSTALL discover product=") + label + L" installedExe=" + FileNameOnly(installed) +
        L" registryCommands=" + std::to_wstring(commands.size()));
    if (matcher==SystemInformerDisplayName && HolyInstalled::StandardSystemInformerLocation(installed)) {
        // Do NOT first execute the in-tree copy: v5 logs show it removes ARP
        // registration but leaves the main EXE. Use the same external pinned
        // setup that completed removal on the second attempt, BEFORE any launch.
        // This is one selected command, not a retry after a wizard/UAC was run.
        std::wstring external;
        if(!PrepareSiRecoveryCommand(installed,external,error)) {
            FullLog(L"UNINSTALL SI external setup refused before launch: "+error);return false;
        }
        FullLog(L"UNINSTALL SI selected external verified setup before first launch; registryCandidates="+std::to_wstring(commands.size()));
        commands.assign(1,external);
    }
    if (commands.empty() && matcher == SystemInformerDisplayName && !installed.empty()) {
        // Repair discovery only, not permissions/trust: the same canonical path,
        // product binding, PE, ACL/signature and UAC checks run below.
        std::vector<std::wstring> roots{HolyInstalled::Parent(installed)};
        const auto arch = LowerAscii(FileNameOnly(roots.front()));
        if (arch == L"amd64" || arch == L"i386" || arch == L"arm64" || arch == L"x64" || arch == L"x86")
            roots.push_back(HolyInstalled::Parent(roots.front()));
        for (const auto& root : roots) {
            const auto setup = JoinPath(root,L"systeminformer-setup.exe");
            if (FileExists(setup)) commands.push_back(L"\"" + setup + L"\" " + HolyUninstall::SystemInformerArguments());
        }
        FullLog(L"UNINSTALL SI local setup candidates=" + std::to_wstring(commands.size()));
    }
    if(commands.empty() && matcher==SystemInformerDisplayName && !installed.empty()) {
        std::wstring recovery;
        if(PrepareSiRecoveryCommand(installed,recovery,error))commands.push_back(recovery);
        else {FullLog(L"UNINSTALL SI recovery refused: "+error);return false;}
    }
    if (commands.empty()) { error = L"Не найдены читаемая команда удаления и локальный штатный деинсталлятор. Подробности: Загрузки\\holycheckfull.txt. Восстановите установку проверенным пакетом или используйте Параметры Windows → Приложения."; return false; }
    for (const auto& command : commands) {
        if (g_cancelRequested.load()) { error = L"Удаление отменено."; return false; }
        bool started = false;
        if (LaunchRegisteredCommandNoWait(label, command, installed, started, error)) {
            // A successful bootstrapper can return BEFORE its interactive child.
            // Wait cooperatively for real removal instead of an immediate error.
            SetUninstallStatus(InstalledProductIndex(label), true);
            unsigned lastObservation=MAXDWORD;
            const auto outcome = HolyUninstall::WaitForRemoval(GetTickCount64() + 10ULL * 60 * 1000,
                [] { return GetTickCount64(); }, [&] {
                    // Vendor uninstallers may finish a tracked app after the
                    // initial graceful-close timeout. Release exited process
                    // objects here, not only on the next click/app shutdown.
                    CleanupExitedTrackedProcesses();
                    HolyUninstall::Observation observation;
                    observation.registered = HasRegisteredProduct(matcher, observation.registryReadable);
                    observation.fileReadable = true; observation.filePresent = false;
                    if (!installed.empty()) {
                        const DWORD attrs = GetFileAttributesW(installed.c_str());
                        const DWORD code = attrs == INVALID_FILE_ATTRIBUTES ? GetLastError() : ERROR_SUCCESS;
                        observation.filePresent = attrs != INVALID_FILE_ATTRIBUTES;
                        observation.fileReadable = observation.filePresent || code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND;
                    }
                    const unsigned flags=(observation.registered?1u:0u)|(observation.registryReadable?2u:0u)|
                        (observation.filePresent?4u:0u)|(observation.fileReadable?8u:0u);
                    if (flags!=lastObservation) {
                        lastObservation=flags;
                        FullLog(std::wstring(L"UNINSTALL observe product=") + label + L" registered=" + std::to_wstring(observation.registered) +
                            L" registryReadable=" + std::to_wstring(observation.registryReadable) + L" filePresent=" + std::to_wstring(observation.filePresent) +
                            L" fileReadable=" + std::to_wstring(observation.fileReadable));
                    }
                    return observation;
                }, [] { return g_cancelRequested.load(); }, [](unsigned ms) { Sleep(ms); });
            FullLog(std::wstring(L"UNINSTALL removal observation product=") + label + L" outcome=" + std::to_wstring(static_cast<int>(outcome)));
            if (outcome == HolyUninstall::Removal::Complete) return true;
            error = outcome == HolyUninstall::Removal::Cancelled
                ? L"Ожидание удаления отменено. Окно деинсталлятора может продолжать работу; файлы HolyCheck сохранены."
                : L"За 10 минут после выхода стартового процесса удаление не подтверждено. Завершите Uninstall в окне программы; если требуется, перезагрузите Windows. Файлы HolyCheck сохранены.";
            return false;
        }
        FullLog(std::wstring(L"UNINSTALL rejected/failed product=") + label + L" started=" + std::to_wstring(started) + L" reason=" + error);
        if (started) return false; // Never invoke a second uninstaller after a launch.
    }
    return false;
}
[[maybe_unused]] static bool LaunchRegisteredSystemInformerUninstallerNoWait(std::wstring& error) {
    return LaunchRegisteredProductUninstallerNoWait(L"System Informer", SystemInformerDisplayName,
                                                    FindInstalledSystemInformerPath(), error);
}
[[maybe_unused]] static bool LaunchRegisteredRecuvaUninstallerNoWait(std::wstring& error) {
    return LaunchRegisteredProductUninstallerNoWait(L"Recuva", RecuvaDisplayName, FindInstalledRecuvaPath(), error);
}
[[maybe_unused]] static bool LaunchRegisteredFtkImagerUninstallerNoWait(std::wstring& error) {
    return LaunchRegisteredProductUninstallerNoWait(L"FTK Imager", FtkImagerDisplayName, FindInstalledFtkImagerPath(), error);
}
[[maybe_unused]] static bool LaunchRegisteredProcessHackerUninstallerNoWait(std::wstring& error) {
    return LaunchRegisteredProductUninstallerNoWait(L"Process Hacker", ProcessHackerDisplayName, FindInstalledProcessHackerPath(), error);
}

// ZIP распаковывается синхронно с проверкой каждого пути и потока данных.
// Никакие PowerShell/cmd/tar/7z процессы для распаковки не запускаются.
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

[[maybe_unused]] static void CollectExecutablesRecursive(const std::wstring& directory,
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
    if (name == L"userassistview") return L"UserAssistView.exe";
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
    if (cachedPath.empty() || cachedHash.empty() || !HolyFiles::StrictChild(cachedPath,ItemExtractDirectory(itemIndex)) || !FileExists(cachedPath)) {
        ClearCachedLaunchPath(itemIndex);
        return {};
    }

    // The extracted directory is user-writable. Re-hash the executable before
    // every later launch so a same-user process cannot silently replace it.
    std::wstring actualHash;
    // This is a candidate hint, not launch authorisation. The complete tree
    // is verified once by OpenTrackedPath while launch locks remain held.
    if (!GetFileSha256Hex(cachedPath, actualHash) ||
        _wcsicmp(actualHash.c_str(), cachedHash.c_str()) != 0) {
        ClearCachedLaunchPath(itemIndex);
        return {};
    }
    return cachedPath;
}

static bool SetCachedLaunchPath(int itemIndex, const std::wstring& path, std::wstring& error) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount ||
        !HolyFiles::StrictChild(path,ItemExtractDirectory(itemIndex)) || !FileExists(path)) return false;
    std::wstring hash;
    std::vector<TrustedExtractedFile> own;
    {std::lock_guard<std::mutex> guard(g_extractedMutex);own=g_extractedFiles[itemIndex];}
    auto member=std::find_if(own.begin(),own.end(),[&](const auto& f){return _wcsicmp(f.path.c_str(),path.c_str())==0;});
    if(member==own.end()){error=L"EXE не входит в проверенный инвентарь архива.";return false;}
    if (!GetFileSha256Hex(path, hash)) { error = L"Не удалось вычислить SHA-256 найденного EXE."; return false; }
    if(hash!=member->sha256){error=L"Выбранный EXE изменён относительно проверенного архива: "+HolyInstalled::Leaf(path)+L".";return false;}
    std::lock_guard<std::mutex> lock(g_launchPathCacheMutex);
    const size_t index = static_cast<size_t>(itemIndex);
    g_launchPathCache[index] = path;
    g_launchHashCache[index] = hash;
    return true;
}

[[maybe_unused]] static std::wstring FindNamedExecutableRecursive(const std::wstring& directory,
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

static std::wstring FindBestExtractedExecutable(int itemIndex, const std::wstring& directory, std::wstring& error) {
    error.clear();
    if (directory != ItemExtractDirectory(itemIndex) || !DirectoryExists(directory)) return {};
    std::vector<TrustedExtractedFile> own;
    { std::lock_guard<std::mutex> guard(g_extractedMutex); own = g_extractedFiles[itemIndex]; }
    std::wstring best; int bestScore = std::numeric_limits<int>::min();
    for (const auto& f : own) {
        if (!EndsWithI(f.path, L".exe") || !FileExists(f.path)) continue;
        const int score = ExecutableCandidateScore(itemIndex, f.path);
        if (score > bestScore) { best = f.path; bestScore = score; }
    }
    FullLog(L"ZIP candidate item=" + std::to_wstring(itemIndex) + L" inventory=" + std::to_wstring(own.size()) + L" exe=" + FileNameOnly(best));
    if (best.empty()) { error = L"Проверенный архив не содержит доступного EXE этой программы."; return {}; }
    if (!SetCachedLaunchPath(itemIndex, best, error)) {
        if (error.empty()) error = L"EXE найден, но проверка распакованной программы не пройдена.";
        FullLog(L"ZIP candidate rejected: " + error); return {};
    }
    return best;
}

void StartDownload(int itemIndex, bool openAfterDownload);
// Compatibility entry points use the same bounded background pipeline.
[[maybe_unused]] static void StartArchiveExtractionAndOpen(int itemIndex) { StartDownload(itemIndex, true); }
[[maybe_unused]] void OpenDownloadedItem(int itemIndex) { StartDownload(itemIndex, true); }
