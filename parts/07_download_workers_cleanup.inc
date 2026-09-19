static bool IsOwnHolyCheckDirectory(const std::wstring& path) {
    if (path.empty()) return false;

    PWSTR localAppData = nullptr;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData);
    if (FAILED(hr) || !localAppData) return false;

    const std::wstring expected = JoinPath(localAppData, L"HolyCheck");
    CoTaskMemFree(localAppData);
    return _wcsicmp(path.c_str(), expected.c_str()) == 0;
}

// Рекурсивно удаляет только переданный каталог. Reparse points/junctions
// не обходятся внутрь, чтобы удаление не могло уйти за пределы HolyCheck.
static bool DeleteDirectoryTreeNoReparse(const std::wstring& directory) {
    DWORD attrs = GetFileAttributesW(directory.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return true;
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0) return false;

    const std::wstring mask = JoinPath(directory, L"*");
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(mask.c_str(), &data);
    bool ok = true;

    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0)
                continue;

            const std::wstring child = JoinPath(directory, data.cFileName);
            const bool isDir = (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const bool isReparse = (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

            if (isDir) {
                if (isReparse) {
                    if (!RemoveDirectoryW(child.c_str())) ok = false;
                } else if (!DeleteDirectoryTreeNoReparse(child)) {
                    ok = false;
                }
            } else {
                if (data.dwFileAttributes & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
                    SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
                if (!DeleteFileW(child.c_str())) ok = false;
            }
        } while (FindNextFileW(find, &data));
        FindClose(find);
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND) {
        ok = false;
    }

    attrs = GetFileAttributesW(directory.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
        if (attrs & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
            SetFileAttributesW(directory.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (!RemoveDirectoryW(directory.c_str())) ok = false;
    }

    return ok;
}

void DeleteAllDownloaded() {
    for (int i = 0; i < static_cast<int>(kItemCount); ++i) {
        if (IsBusy(i)) {
            MessageBoxW(g_mainWindow,
                        L"Сначала дождитесь завершения текущих загрузок или распаковки.",
                        L"HolyCheck", MB_OK | MB_ICONINFORMATION);
            return;
        }
    }

    bool expected = false;
    if (!g_deleteAllBusy.compare_exchange_strong(expected, true))
        return;

    HWND target = g_mainWindow;
    std::thread([target]() {
        const HRESULT coHr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool shouldUninitialize = SUCCEEDED(coHr);

        std::unique_ptr<DeleteAllMessage> result(new DeleteAllMessage());

        std::wstring registeredCommand;
        result->systemInformerWasInstalled =
            !FindInstalledSystemInformerPath().empty() ||
            FindSystemInformerUninstallCommand(registeredCommand);
        registeredCommand.clear();
        result->recuvaWasInstalled =
            !FindInstalledRecuvaPath().empty() ||
            FindInstalledProductUninstallCommand(RecuvaDisplayName, registeredCommand);
        registeredCommand.clear();
        result->ftkImagerWasInstalled =
            !FindInstalledFtkImagerPath().empty() ||
            FindInstalledProductUninstallCommand(FtkImagerDisplayName, registeredCommand);

        for (int i = 0; i < static_cast<int>(kItemCount); ++i) {
            const bool downloaded = FileExists(ItemPath(i));
            const std::wstring extracted = ItemExtractDirectory(i);
            const bool unpacked = !extracted.empty() && DirectoryExists(extracted);
            if (downloaded || unpacked) result->existingItems.push_back(i);
        }

        // This can wait briefly for normal WM_CLOSE processing, but it runs on
        // a worker thread so the HolyCheck window remains fully responsive.
        CloseTrackedProgramsGracefully();

        // Start only the uninstallers registered by Windows/the publisher.
        // No process-name killing, cmd.exe, PowerShell or GUI automation.
        if (result->systemInformerWasInstalled) {
            result->systemInformerUninstallStarted =
                LaunchRegisteredSystemInformerUninstallerNoWait(result->systemInformerError);
        }
        if (result->recuvaWasInstalled) {
            result->recuvaUninstallStarted =
                LaunchRegisteredRecuvaUninstallerNoWait(result->recuvaError);
        }
        if (result->ftkImagerWasInstalled) {
            result->ftkImagerUninstallStarted =
                LaunchRegisteredFtkImagerUninstallerNoWait(result->ftkImagerError);
        }

        if (DirectoryExists(g_appDir)) {
            if (!IsOwnHolyCheckDirectory(g_appDir)) {
                result->localOk = false;
            } else {
                result->localOk = DeleteDirectoryTreeNoReparse(g_appDir) &&
                                  !DirectoryExists(g_appDir);
            }
        }

        if (!PostMessageW(target, WM_APP_DELETE_ALL_DONE, 0,
                          reinterpret_cast<LPARAM>(result.get()))) {
            g_deleteAllBusy.store(false);
            if (shouldUninitialize) CoUninitialize();
            return;
        }
        result.release();
        if (shouldUninitialize) CoUninitialize();
    }).detach();
}
