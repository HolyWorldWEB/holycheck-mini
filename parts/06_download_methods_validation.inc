// Existing v13 packages can be reused without redownloading. Retain the old
// tree for compatibility; never blindly move/delete shared DLLs or user data.
static bool ReusePreviousSsPayload(int item,std::wstring& error) {
    if(!HolyStorage::MovedToSs(kItems[item].name)||FileExists(ItemPath(item)))return true;
    const auto previous=JoinPath(HolyStorage::TabPath(g_appDir,3),kItems[item].file);
    if(!FileExists(previous))return true;
    std::scoped_lock<std::recursive_mutex,std::recursive_mutex> guard(g_tabFileMutex[3],g_tabFileMutex[4]);
    if(FileExists(ItemPath(item)))return true;
    HandleSet source,destination;
    if(!LockRegularFile(previous,source)||!VerifyPinnedPayloadForItem(item,previous,error)||
       !LockDirectoryChain(ItemDirectory(item),destination)) {
        if(error.empty())error=L"Не удалось безопасно прочитать прежний пакет программы.";return false;
    }
    const HANDLE input=source.handles.back();LARGE_INTEGER size{};
    if(!GetFileSizeEx(input,&size)||size.QuadPart<0||size.QuadPart>2LL*1024*1024*1024) {
        error=L"Недопустимый размер прежнего пакета.";return false;
    }
    const auto part=ItemPath(item)+L".reuse.part";
    HANDLE output=CreateFileW(part.c_str(),GENERIC_READ|GENERIC_WRITE|DELETE,0,nullptr,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(output==INVALID_HANDLE_VALUE){error=L"Не удалось создать новый пакет ss: "+Win32ErrorText(GetLastError());return false;}
    struct OutputScope {
        HANDLE file;bool published=false;
        ~OutputScope(){
            if(!published){FILE_DISPOSITION_INFO remove{TRUE};
                if(!SetFileInformationByHandle(file,FileDispositionInfo,&remove,sizeof(remove)))
                    FullLog(L"SS own partial cleanup failed code="+std::to_wstring(GetLastError()));}
            CloseHandle(file);
        }
    } scope{output};
    std::array<unsigned char,65536> buffer{};
    for(uint64_t at=0;at<static_cast<uint64_t>(size.QuadPart);) {
        if(g_cancelRequested.load()){error=L"Операция отменена.";return false;}
        const DWORD count=static_cast<DWORD>(std::min<uint64_t>(buffer.size(),static_cast<uint64_t>(size.QuadPart)-at));
        DWORD written=0;
        if(!ReadAt(input,at,buffer.data(),count)||!WriteFile(output,buffer.data(),count,&written,nullptr)||written!=count) {
            error=L"Ошибка копирования проверенного прежнего пакета.";return false;
        }
        at+=count;
    }
    if(!FlushFileBuffers(output)||!VerifyPinnedPayloadForItem(item,part,error,output)||
       !BasicPayloadCheck(part,kItems[item].file,output)||g_cancelRequested.load()) {
        if(error.empty())error=L"Не удалось подтвердить копию прежнего пакета или операция отменена.";return false;
    }
    if(!PublishOpenDownload(output,ItemPath(item))){error=L"Файл ss уже существует или публикация пакета не удалась.";return false;}
    scope.published=true;
    FullLog(L"SS reused verified previous payload item="+std::to_wstring(item));return true;
}

// One operation per item. All scanning, hashing, extraction and ShellExecute
// run on the bounded pool; only the UI consumes completion messages.
void StartDownload(int itemIndex, bool openAfterDownload = true) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount ||
        g_closeWhenIdle || g_cancelRequested.load() || g_deleteAllBusy.load() || !MarkBusy(itemIndex)) return;
    RefreshItemButtons(itemIndex);
    g_itemProgress[static_cast<size_t>(itemIndex)].store(0);
    const HWND target = g_mainWindow;
    const auto queuedAt=GetTickCount64();
    StartWorker(itemIndex, [target, itemIndex, openAfterDownload, queuedAt] {
        const auto workerStarted=GetTickCount64();
        struct ComScope {
            HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            ~ComScope() { if (SUCCEEDED(hr)) CoUninitialize(); }
        } com;
        if(kItems[itemIndex].website) {
            auto result=std::make_unique<DownloadMessage>();result->itemIndex=itemIndex;
            result->showError=openAfterDownload;
            result->ok=!g_cancelRequested.load()&&HolyUi::AllowedWebsite(kItems[itemIndex].url);
            if(result->ok&&openAfterDownload) {
                SHELLEXECUTEINFOW launch{};launch.cbSize=sizeof(launch);
                launch.fMask=SEE_MASK_NOASYNC|SEE_MASK_FLAG_NO_UI|SEE_MASK_NOCLOSEPROCESS;
                launch.lpVerb=L"open";launch.lpFile=kItems[itemIndex].url;launch.nShow=SW_SHOWNORMAL;
                if(g_cancelRequested.load())result->ok=false;
                else {result->ok=ShellExecuteExW(&launch)!=FALSE;result->launched=result->ok;
                    if(!result->ok)result->text=L"Не удалось открыть сайт в браузере: "+Win32ErrorText(GetLastError());
                    if(launch.hProcess)CloseHandle(launch.hProcess);}
            }
            if(!result->ok&&result->text.empty())result->text=L"Открытие сайта отменено либо адрес не разрешён.";
            FullLog(L"WEBSITE item="+std::to_wstring(itemIndex)+L" ok="+std::to_wstring(result->ok));
            if(!PostDownloadResult(target,std::move(result)))MarkIdle(itemIndex);
            return; // No file path, SHA bypass, download, installer or browser tracking.
        }
        ScopedHashReads verifiedReads(itemIndex);
        // Network and independent payload checks must not occupy the shared
        // tab lock. Only extraction/tree verification/launch mutate/use the
        // shared executable namespace; publication takes its own short lock.
        std::unique_lock<std::recursive_mutex> tabGuard(g_tabFileMutex[kItems[itemIndex].tab],std::defer_lock);
        auto result = std::make_unique<DownloadMessage>();
        result->itemIndex = itemIndex;
        result->openAfterDownload = false;
        result->showError = openAfterDownload;
        FullLog(std::wstring(L"ITEM start name=") + kItems[itemIndex].name + L" open=" + std::to_wstring(openAfterDownload));
        FullLog(L"PIPELINE item="+std::to_wstring(itemIndex)+L" queueMs="+std::to_wstring(workerStarted-queuedAt)+L" setupMs="+std::to_wstring(GetTickCount64()-workerStarted));
        if(openAfterDownload&&!g_cancelRequested.load()&&!IsReportedUnsafePayload(itemIndex)&&
            !IsSystemInformerItemIndex(itemIndex)&&!IsFtkImagerItemIndex(itemIndex)&&
            !IsRecuvaItemIndex(itemIndex)&&!IsProcessHackerItemIndex(itemIndex)&&ActivateAlreadyRunningItem(itemIndex,L"")) {
            result->ok=true;result->launched=true;
            FullLog(L"ITEM activated existing process item="+std::to_wstring(itemIndex));
            if(!PostDownloadResult(target,std::move(result)))MarkIdle(itemIndex);
            return;
        }
        std::wstring error, launchPath;
        bool ok = !g_cancelRequested.load();
        if(!ok)error=L"Операция отменена.";
        else if(!HasPinnedSha256(itemIndex)){ok=false;error=L"Для этой программы не задан проверенный SHA-256.";}
        if (ok && IsSystemInformerItemIndex(itemIndex)) launchPath = FindInstalledSystemInformerPath();
        if (ok && IsRecuvaItemIndex(itemIndex)) launchPath = FindInstalledRecuvaPath();
        if (ok && IsFtkImagerItemIndex(itemIndex)) launchPath = FindInstalledFtkImagerPath();
        if (ok && IsProcessHackerItemIndex(itemIndex)) launchPath = FindInstalledProcessHackerPath();
        if (ok && openAfterDownload && launchPath.empty()) {
            InstalledProductDisplayMatcher matcher = nullptr;
            if (IsSystemInformerItemIndex(itemIndex)) matcher = SystemInformerDisplayName;
            else if (IsFtkImagerItemIndex(itemIndex)) matcher = FtkImagerDisplayName;
            else if (IsRecuvaItemIndex(itemIndex)) matcher = RecuvaDisplayName;
            else if (IsProcessHackerItemIndex(itemIndex)) matcher = ProcessHackerDisplayName;
            if (matcher) {
                bool readable = true;
                const bool registered = HasRegisteredProduct(matcher, readable);
                if (registered || !readable) {
                    ok = false;
                    error = L"Установка обнаружена или её состояние недоступно, но основной EXE не найден. "
                            L"Повторный запуск установщика заблокирован. Проверьте расположение/восстановите установку через Параметры Windows.";
                }
            }
        }
        if (ok && launchPath.empty()) {
            // Validate signed metadata BEFORE deleting an existing payload or
            // contacting its server. Expired/missing state is not a reason to
            // erase an otherwise intact local file and redownload blindly.
            std::wstring expected;
            ok = ExpectedPayloadHash(itemIndex, expected, error);
        }
        if (ok && launchPath.empty()) {
            // Startup established these paths. Recreate them after Delete All
            // without writing global strings from worker threads.
            HandleSet dirs;
            ok = EnsureTabDirectories() && LockDirectoryChain(ItemDirectory(itemIndex), dirs);
            if (!ok) error = L"Недоступен или небезопасен каталог HolyCheck.";
            const auto path = ItemPath(itemIndex);
            if(ok&&!FileExists(path))ok=ReusePreviousSsPayload(itemIndex,error);
            bool valid = false;
            if (ok && FileExists(path)) {
                HandleSet locks;
                valid = LockRegularFile(path, locks) &&
                        VerifyPinnedPayloadForItem(itemIndex, path, error) &&
                        BasicPayloadCheck(path, kItems[itemIndex].file);
                // Invalid existing files are preserved; no delete-and-redownload fallback.
            }
            if (ok && !valid) {
                // Bulk download does not confuse existence with authenticity.
                if (FileExists(path)) {
                    ok = false; error = L"По имени загрузки уже существует непроверенный/изменённый файл. Он сохранён: " + HolyInstalled::Leaf(path) + L". Переместите его отдельно и повторите загрузку.";
                }
                if (ok && !g_cancelRequested.load()) {
                    ok = DownloadHttpsFile(itemIndex, kItems[itemIndex].url, path,
                                           kItems[itemIndex].file, error);
                    result->downloaded = ok;
                } else if (ok) { ok = false; error = L"Операция отменена."; }
                ClearCachedLaunchPath(itemIndex);
            }
            if (ok && openAfterDownload && EndsWithI(kItems[itemIndex].file, L".zip")) {
                const auto lockAt=GetTickCount64();tabGuard.lock();
                FullLog(L"EXTRACT item="+std::to_wstring(itemIndex)+L" lockWaitMs="+std::to_wstring(GetTickCount64()-lockAt));
                if(g_cancelRequested.load()){ok=false;error=L"Операция отменена.";}
                launchPath = GetCachedLaunchPath(itemIndex);
                if (ok && launchPath.empty()) {
                    const auto destination = ItemExtractDirectory(itemIndex);
                    ClearCachedLaunchPath(itemIndex);
                    // Rebuild trust from the pinned archive, but do not run a
                    // second extraction/parent-walk when its files already exist.
                    ok = LoadArchiveInventory(itemIndex, error);
                    if(ok && HaveArchiveFilesOnDisk(itemIndex)) {
                        FullLog(L"ZIP reuse existing files item="+std::to_wstring(itemIndex));
                    } else if(ok) {
                        // Missing files use the normal collision-safe extractor.
                        ok = ExtractVerifiedZip(itemIndex, path, destination, error);
                    }
                    if (ok) {
                        launchPath = FindBestExtractedExecutable(itemIndex, destination, error);
                        ok = !launchPath.empty();
                        if (!ok && error.empty()) error = L"Не удалось выбрать проверенный EXE из архива.";
                    }
                    // ExtractVerifiedZip rolls back only files created by this operation.
                }
            } else if (ok) launchPath = path;
        }
        if (ok && g_cancelRequested.load()) { ok = false; error = L"Операция отменена."; }
        if (ok && openAfterDownload) {
            const auto launchAt=GetTickCount64();
            ok = OpenTrackedPath(itemIndex, launchPath, error);
            FullLog(L"OPEN item="+std::to_wstring(itemIndex)+L" verifyAndShellMs="+std::to_wstring(GetTickCount64()-launchAt));
            result->launched = ok;
        }
        if(g_cancelRequested.load()){ok=false;error=L"Операция отменена.";}
        FullLog(std::wstring(L"ITEM completed name=") + kItems[itemIndex].name + L" ok=" + std::to_wstring(ok) + L" downloaded=" + std::to_wstring(result->downloaded) + L" launched=" + std::to_wstring(result->launched) + L" reason=" + error);
        result->ok = ok;
        result->text = error;
        if (!PostDownloadResult(target, std::move(result))) MarkIdle(itemIndex);
    }, openAfterDownload);
}

void DownloadCurrentTab() {
    for (int i = 0; i < static_cast<int>(kItemCount); ++i)
        if (kItems[i].tab == g_currentTab&&!kItems[i].website) StartDownload(i, false);
}
