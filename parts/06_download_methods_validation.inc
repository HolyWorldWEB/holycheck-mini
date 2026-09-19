void StartDownload(int itemIndex, bool openAfterDownload = true) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return;
    if (g_deleteAllBusy.load()) return;

    // Release builds are fail-closed: never contact the network for an item
    // whose exact payload has not been pinned.
    if (!HasPinnedSha256(itemIndex)) {
        MessageBoxW(g_mainWindow,
                    L"Для этой программы пока нет проверенного SHA-256.\nЗагрузка отключена до фиксации хеша.",
                    L"HolyCheck", MB_OK | MB_ICONWARNING);
        return;
    }

    // System Informer is special: once installed, the tile opens the installed
    // application and never launches the downloaded setup again.
    if (IsSystemInformerItemIndex(itemIndex) && !FindInstalledSystemInformerPath().empty()) {
        if (openAfterDownload) OpenDownloadedItem(itemIndex);
        return;
    }
    if (IsRecuvaItemIndex(itemIndex) && !FindInstalledRecuvaPath().empty()) {
        if (openAfterDownload) OpenDownloadedItem(itemIndex);
        return;
    }
    if (IsFtkImagerItemIndex(itemIndex) && !FindInstalledFtkImagerPath().empty()) {
        if (openAfterDownload) OpenDownloadedItem(itemIndex);
        return;
    }

    // Если файл уже есть, обычный клик открывает его. Для массовой загрузки
    // существующие файлы просто пропускаются.
    const std::wstring existingPath = ItemPath(itemIndex);
    if (!existingPath.empty() && FileExists(existingPath)) {
        if (openAfterDownload) OpenDownloadedItem(itemIndex);
        return;
    }

    if (!InitDownloadDirectory()) {
        MessageBoxW(g_mainWindow, L"Не удалось создать папку HolyCheck в LocalAppData.",
                    L"HolyCheck", MB_OK | MB_ICONERROR);
        return;
    }

    if (!MarkBusy(itemIndex)) return;

    std::wstring finalPath = ItemPath(itemIndex);
    if (finalPath.empty()) {
        MarkIdle(itemIndex);
        MessageBoxW(g_mainWindow, L"Недопустимое имя файла.", L"HolyCheck", MB_OK | MB_ICONERROR);
        return;
    }

    RefreshItemButtons(itemIndex);
    g_itemProgress[static_cast<size_t>(itemIndex)].store(0);
    InvalidateRect(g_mainWindow, nullptr, FALSE);

    const std::wstring url = kItems[itemIndex].url;
    const std::wstring fileName = kItems[itemIndex].file;
    HWND target = g_mainWindow;

    std::thread([target, itemIndex, url, finalPath, fileName, openAfterDownload]() {
        std::wstring error;
        bool ok = DownloadHttpsFile(itemIndex, url, finalPath, fileName, error);
        auto message = std::make_unique<DownloadMessage>();
        message->itemIndex = itemIndex;
        message->ok = ok;
        message->openAfterDownload = openAfterDownload;
        message->text = error;
        if (!PostDownloadResult(target, std::move(message))) {
            MarkIdle(itemIndex);
        }
    }).detach();
}

void DownloadCurrentTab() {
    if (!InitDownloadDirectory()) {
        MessageBoxW(g_mainWindow, L"Не удалось создать папку HolyCheck в LocalAppData.",
                    L"HolyCheck", MB_OK | MB_ICONERROR);
        return;
    }

    // "Скачать все" скачивает все программы текущей вкладки, но не запускает
    // их пачкой. Автооткрытие выполняется только при клике по отдельной плитке.
    for (int i = 0; i < static_cast<int>(kItemCount); ++i) {
        if (kItems[i].tab == g_currentTab && HasPinnedSha256(i) &&
            !IsItemAlreadyAvailable(i) && !IsBusy(i)) {
            StartDownload(i, false);
        }
    }
}
