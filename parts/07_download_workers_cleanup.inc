// The Delete button has exactly one target: the system Downloads\HolyCheck.
// Vendor uninstallers run separately; this file deletion plan never targets
// Program Files, registry keys, Downloads itself or scheduled tasks.
struct FolderDeleteNode {
    std::wstring path;
    HANDLE handle = INVALID_HANDLE_VALUE;
    bool directory = false;
};
struct FolderDeletePlan {
    HandleSet parents;
    BY_HANDLE_FILE_INFORMATION protectedImage{};
    bool protectImage=false;
    std::vector<FolderDeleteNode> nodes; // preorder; commit in reverse order
    ~FolderDeletePlan() { for (auto& node:nodes) if(node.handle!=INVALID_HANDLE_VALUE) CloseHandle(node.handle); }
    FolderDeletePlan() = default;
    FolderDeletePlan(const FolderDeletePlan&) = delete;
    FolderDeletePlan& operator=(const FolderDeletePlan&) = delete;
};
static bool FolderFailure(std::wstring& error,const std::wstring& path,DWORD code) {
    if(!code)code=ERROR_GEN_FAILURE;
    // Log only the leaf, not the user's full profile path.
    (void)0;
    std::wstring hint;
    if(code==ERROR_DIR_NOT_EMPTY)
        hint=L" Windows ещё видит содержимое папки: удаление может ожидать освобождения файлов либо в папке появились новые данные. Новые объекты повторно не удалялись.";
    else if(code==ERROR_SHARING_VIOLATION||code==ERROR_LOCK_VIOLATION)
        hint=L" Объект занят. Завершите работу использующей его программы и повторите.";
    else if(code==ERROR_ACCESS_DENIED)
        hint=L" Доступ запрещён либо путь не прошёл проверку безопасности. Проверьте права доступа.";
    error=L"Папка HolyCheck не удалена полностью. Объект: "+HolyInstalled::Leaf(path)+
        L". "+Win32ErrorText(code)+hint+L"";
    SetLastError(code);return false;
}
static bool AddFolderDeleteNode(const std::wstring& root,const std::wstring& path,
                                FolderDeletePlan& plan,std::wstring& error,unsigned depth=0) {
    if(g_cancelRequested.load())return FolderFailure(error,path,ERROR_CANCELLED);
    if(!HolyFiles::FolderTarget(path,root))
        return FolderFailure(error,path,ERROR_ACCESS_DENIED);
    // Bounds prevent hostile/deep trees from exhausting the stack or handles.
    if(depth>128||plan.nodes.size()>=16384)return FolderFailure(error,path,ERROR_TOO_MANY_OPEN_FILES);
    HANDLE h=CreateFileW(path.c_str(),DELETE|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|FILE_LIST_DIRECTORY,
        FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h==INVALID_HANDLE_VALUE)return FolderFailure(error,path,GetLastError());
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(h,&info)){const auto code=GetLastError();CloseHandle(h);return FolderFailure(error,path,code);}
    const bool directory=(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0;
    if(plan.protectImage&&info.dwVolumeSerialNumber==plan.protectedImage.dwVolumeSerialNumber&&
       info.nFileIndexHigh==plan.protectedImage.nFileIndexHigh&&info.nFileIndexLow==plan.protectedImage.nFileIndexLow) {
        CloseHandle(h);error=L"HolyCheck.exe находится внутри удаляемой папки (включая псевдоним пути). Перенесите его за её пределы и повторите.";
        SetLastError(ERROR_ACCESS_DENIED);return false;
    }
    // Never follow junctions/symlinks, and don't touch multiply-linked files.
    if((info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||(!directory&&info.nNumberOfLinks!=1)||
       (_wcsicmp(path.c_str(),root.c_str())==0&&!directory)) {
        CloseHandle(h);return FolderFailure(error,path,ERROR_ACCESS_DENIED);
    }
    try{plan.nodes.push_back({path,h,directory});}catch(...){CloseHandle(h);throw;}
    if(!directory)return true;
    WIN32_FIND_DATAW data{};HANDLE find=FindFirstFileW(JoinPath(path,L"*").c_str(),&data);
    if(find==INVALID_HANDLE_VALUE) {
        const auto code=GetLastError();return code==ERROR_FILE_NOT_FOUND||FolderFailure(error,path,code);
    }
    struct FindScope{HANDLE h;~FindScope(){FindClose(h);}} scope{find};
    do {
        const std::wstring name=data.cFileName;
        if(name==L"."||name==L"..")continue;
        if(!HolyFiles::SafeComponent(name))return FolderFailure(error,name,ERROR_INVALID_NAME);
        if(!AddFolderDeleteNode(root,JoinPath(path,name),plan,error,depth+1))return false;
    }while(FindNextFileW(find,&data));
    const DWORD code=GetLastError();return code==ERROR_NO_MORE_FILES||FolderFailure(error,path,code);
}
static bool BuildFolderDeletePlan(const std::wstring& root,FolderDeletePlan& plan,std::wstring& error) {
    // Ancestors remain pinned, but are NEVER in the deletion list.
    if(!HolyFiles::LocalPath(root)||!LockDirectoryChain(HolyInstalled::Parent(root),plan.parents))
        return FolderFailure(error,root,GetLastError()?GetLastError():ERROR_ACCESS_DENIED);
    return AddFolderDeleteNode(root,root,plan,error);
}
static bool FolderResourcesIdle(const FolderDeletePlan& plan,std::wstring& error) {
    std::vector<LPCWSTR> files;
    for(const auto& node:plan.nodes)if(!node.directory)files.push_back(node.path.c_str());
    if(files.empty())return true;
    DWORD session=0;wchar_t key[CCH_RM_SESSION_KEY+1]{};
    DWORD code=RmStartSession(&session,0,key);
    if(code!=ERROR_SUCCESS)return FolderFailure(error,L"Restart Manager",code);
    struct RmScope{DWORD id;~RmScope(){RmEndSession(id);}} scope{session};
    // One registration, not an expensive call for every file. Read-only query:
    // never RmShutdown/RmRestart or terminate a process unrelated to our launches.
    code=RmRegisterResources(session,static_cast<UINT>(files.size()),files.data(),0,nullptr,0,nullptr);
    if(code!=ERROR_SUCCESS)return FolderFailure(error,L"Restart Manager",code);
    UINT needed=0,count=0;DWORD reboot=0;
    std::vector<RM_PROCESS_INFO> users;
    for(unsigned attempt=0;attempt<4;++attempt) {
        count=static_cast<UINT>(users.size());needed=0;reboot=0;
        code=RmGetList(session,&needed,&count,users.empty()?nullptr:users.data(),&reboot);
        if(code!=ERROR_MORE_DATA)break;
        if(!needed||needed>4096)return FolderFailure(error,L"Restart Manager",ERROR_NOT_ENOUGH_MEMORY);
        users.resize(needed);
    }
    if(code!=ERROR_SUCCESS)return FolderFailure(error,L"Restart Manager",code);
    if(count>users.size())return FolderFailure(error,L"Restart Manager",ERROR_INVALID_DATA);
    unsigned otherProcesses=0;
    for(UINT i=0;i<count;++i) {
        // Our own preflight handles can legitimately appear in RM's list.
        // Ignore only THIS live process, not any other HolyCheck instance.
        if(users[i].Process.dwProcessId!=GetCurrentProcessId())++otherProcesses;
    }
    // Self-detection can be caused by OUR retained preflight handles. Other
    // reboot reasons remain fail-closed; this is not RmShutdown permission.
    const DWORD blockingReboot=reboot&~static_cast<DWORD>(RmRebootReasonDetectedSelf);
    if(otherProcesses||blockingReboot) {
        error=L"Файлы HolyCheck ещё используются программой или службой. Закройте её и повторите удаление. Папка пока не изменена.";
        (void)0;
        SetLastError(ERROR_SHARING_VIOLATION);return false;
    }
    return true;
}

static bool WaitFolderRetry(unsigned milliseconds) {
    while(milliseconds) {
        if(g_cancelRequested.load())return false;
        const DWORD slice=std::min(milliseconds,25u);
        Sleep(slice);milliseconds-=slice;
    }
    return !g_cancelRequested.load();
}
static bool ConfirmFolderAbsent(const std::wstring& root,HolyFiles::DeleteRetryBudget& budget,std::wstring& error) {
    // READ ONLY: never rebuild a plan or delete a newly appearing object at root.
    const auto code=HolyFiles::RetryDisposition([&]() -> unsigned {
        const DWORD attributes=GetFileAttributesW(root.c_str());
        if(attributes==INVALID_FILE_ATTRIBUTES) {
            const DWORD why=GetLastError();
            if(why==ERROR_FILE_NOT_FOUND||why==ERROR_PATH_NOT_FOUND)return ERROR_SUCCESS;
            // Delete-pending directories can return ACCESS_DENIED. Waiting here
            // is read-only, unlike retrying an unsafe/permanent mutation.
            return why==ERROR_ACCESS_DENIED?ERROR_DIR_NOT_EMPTY:why;
        }
        if(attributes&FILE_ATTRIBUTE_REPARSE_POINT)return ERROR_ACCESS_DENIED;
        return ERROR_DIR_NOT_EMPTY;
    },[]{return g_cancelRequested.load();},WaitFolderRetry,budget);
    if(code)return FolderFailure(error,root,code);
    (void)0;return true;
}
static bool CommitFolderDeletePlan(FolderDeletePlan& plan,std::wstring& error) {
    if(plan.nodes.empty())return FolderFailure(error,L"HolyCheck",ERROR_INVALID_DATA);
    HolyFiles::DeleteRetryBudget budget;
    for(auto it=plan.nodes.rbegin();it!=plan.nodes.rend();++it) {
        if(g_cancelRequested.load())return FolderFailure(error,it->path,ERROR_CANCELLED);
        FILE_BASIC_INFO basic{};
        if(!GetFileInformationByHandleEx(it->handle,FileBasicInfo,&basic,sizeof(basic)))
            return FolderFailure(error,it->path,GetLastError());
        const FILE_BASIC_INFO original=basic;
        const bool wasReadonly=(basic.FileAttributes&FILE_ATTRIBUTE_READONLY)!=0;
        if(wasReadonly) {
            basic.FileAttributes&=~FILE_ATTRIBUTE_READONLY;
            if(!basic.FileAttributes)basic.FileAttributes=FILE_ATTRIBUTE_NORMAL;
            if(!SetFileInformationByHandle(it->handle,FileBasicInfo,&basic,sizeof(basic)))
                return FolderFailure(error,it->path,GetLastError());
        }
        FILE_DISPOSITION_INFO disposition{TRUE};
        unsigned attempts=0;
        const auto code=HolyFiles::RetryDisposition([&]() -> unsigned {
            ++attempts;
            if(SetFileInformationByHandle(it->handle,FileDispositionInfo,&disposition,sizeof(disposition)))return ERROR_SUCCESS;
            const DWORD why=GetLastError();
            if(attempts==1&&HolyFiles::RetryableDisposition(why))
                (void)0;
            return why;
        },[]{return g_cancelRequested.load();},WaitFolderRetry,budget);
        if(code) {
            if(wasReadonly) { FILE_BASIC_INFO restore=original;
                if(!SetFileInformationByHandle(it->handle,FileBasicInfo,&restore,sizeof(restore)))
                    (void)0; }
            return FolderFailure(error,it->path,code);
        }
        CloseHandle(it->handle);it->handle=INVALID_HANDLE_VALUE;
        (void)0;
    }
    return ConfirmFolderAbsent(plan.nodes.front().path,budget,error);
}

static bool SameLaunchIdentity(const ApprovedLaunchTarget& a,const ApprovedLaunchTarget& b) {
    return a.valid&&b.valid&&a.identity.dwVolumeSerialNumber==b.identity.dwVolumeSerialNumber&&
        a.identity.nFileIndexHigh==b.identity.nFileIndexHigh&&a.identity.nFileIndexLow==b.identity.nFileIndexLow;
}
static bool MatchesApprovedLaunchTarget(const std::wstring& image,const std::vector<ApprovedLaunchTarget>& targets) {
    for(const auto& target:targets)if(target.valid&&_wcsicmp(image.c_str(),target.path.c_str())==0) {
        ApprovedLaunchTarget actual;
        return CaptureApprovedLaunchTarget(image,actual)&&SameLaunchIdentity(target,actual);
    }
    return false;
}
struct FolderCloseContext {
    const std::map<DWORD,HANDLE>* processes;
    std::set<std::pair<DWORD,UINT_PTR>>* posted;
    bool denied=false;unsigned requests=0;
};
static BOOL CALLBACK CloseFolderProcessWindow(HWND hwnd,LPARAM parameter) {
    auto* ctx=reinterpret_cast<FolderCloseContext*>(parameter);DWORD pid=0;
    GetWindowThreadProcessId(hwnd,&pid);
    const auto it=ctx->processes->find(pid);
    if(it==ctx->processes->end()||!IsProcessStillRunning(it->second))return TRUE;
    // Do not auto-dismiss a modal save/evidence dialog. Ask only the application's
    // own top-level windows; revisit disabled/not-yet-created windows next pass.
    if(GetWindow(hwnd,GW_OWNER)||!IsWindowEnabled(hwnd))return TRUE;
    const auto key=std::make_pair(pid,reinterpret_cast<UINT_PTR>(hwnd));
    if(ctx->posted->count(key))return TRUE;
    if(PostMessageW(hwnd,WM_CLOSE,0,0)) {ctx->posted->insert(key);++ctx->requests;}
    else {
        const auto code=GetLastError();
        (void)0;
        if(code==ERROR_ACCESS_DENIED)ctx->denied=true;
    }
    return TRUE;
}
static bool CloseFolderProgramsAndWait(const std::wstring& root,std::wstring& error) {
    HandleSet retained,ftkLocks;
    std::map<DWORD,HANDLE> processes;
    std::set<std::pair<DWORD,UINT_PTR>> posted;
    std::vector<ApprovedLaunchTarget> targets;
    {std::lock_guard<std::mutex> guard(g_processMutex);
     for(const auto& target:g_approvedLaunchTargets)if(target.valid)targets.push_back(target);}
    // FTK can reuse an existing installed instance while ShellExecute's process
    // exits. Resolve the actual verified FTK target, not a basename/process name.
    const int ftkIndex=InstalledProductIndex(L"FTK Imager");
    const auto installedFtk=FindInstalledFtkImagerPath();
    bool ftkVerified=installedFtk.empty();
    if(!installedFtk.empty()&&ftkIndex>=0) {
        std::wstring why;ApprovedLaunchTarget ftk;
        ftkVerified=LockRegularFile(installedFtk,ftkLocks)&&VerifyInstalledProgramTrust(ftkIndex,installedFtk,why)&&
            CaptureApprovedLaunchTarget(installedFtk,ftk);
        if(ftkVerified) {targets.push_back(ftk);(void)0;}
        else (void)0;
    }
    const ULONGLONG deadline=GetTickCount64()+60000;
    struct WaitingScope{~WaitingScope(){SetCleanupWaiting(false);}} waiting;
    for(;;) {
        if(g_cancelRequested.load())return FolderFailure(error,root,ERROR_CANCELLED);
        CleanupExitedTrackedProcesses();
        {
            std::lock_guard<std::mutex> guard(g_processMutex);
            for(const auto& entry:g_launchedProcesses)if(IsProcessStillRunning(entry.process)&&!processes.count(entry.pid)) {
                HANDLE duplicate=nullptr;
                if(!DuplicateHandle(GetCurrentProcess(),entry.process,GetCurrentProcess(),&duplicate,SYNCHRONIZE,FALSE,0))
                    return FolderFailure(error,root,GetLastError());
                retained.Add(duplicate);processes.emplace(entry.pid,duplicate);
            }
        }
        HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        if(snapshot==INVALID_HANDLE_VALUE)return FolderFailure(error,root,GetLastError());
        struct SnapshotScope{HANDLE h;~SnapshotScope(){CloseHandle(h);}} snapshots{snapshot};
        PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
        if(!Process32FirstW(snapshot,&entry))return FolderFailure(error,root,GetLastError());
        do {
            if(entry.th32ProcessID==GetCurrentProcessId()||processes.count(entry.th32ProcessID))continue;
            HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,entry.th32ProcessID);
            if(!process) {
                // A basename is NOT permission to close a process. It is only
                // a conservative reason to stop when FTK cannot be identified.
                if(LooksLikeFtkImagerExecutable(entry.szExeFile)) {
                    error=L"Возможный процесс FTK Imager недоступен для проверки. Закройте FTK вручную либо запустите HolyCheck с теми же правами. Папка не изменена.";
                    return false;
                }
                continue;
            }
            wchar_t image[32768]{};DWORD length=ARRAYSIZE(image);
            bool belongs=false;
            if(QueryFullProcessImageNameW(process,0,image,&length)) {
                const std::wstring path(image,length);
                if(!ftkVerified&&_wcsicmp(path.c_str(),installedFtk.c_str())==0&&IsProcessStillRunning(process)) {
                    CloseHandle(process);error=L"FTK Imager работает, но его файл не удалось подтвердить. Закройте FTK вручную и повторите удаление. Папка не изменена.";return false;
                }
                belongs=HolyFiles::StrictChild(path,root)||MatchesApprovedLaunchTarget(path,targets);
                if(!belongs&&LooksLikeFtkImagerExecutable(path)&&IsProcessStillRunning(process)) {
                    CloseHandle(process);error=L"Обнаружен другой экземпляр FTK Imager, путь которого не подтверждён. Закройте его вручную и повторите. Папка не изменена.";return false;
                }
            } else if(LooksLikeFtkImagerExecutable(entry.szExeFile)) {
                CloseHandle(process);error=L"Не удалось проверить путь работающего FTK Imager. Закройте его вручную и повторите. Папка не изменена.";return false;
            }
            if(belongs&&IsProcessStillRunning(process)) {
                if(processes.size()>=4096){CloseHandle(process);return FolderFailure(error,root,ERROR_TOO_MANY_OPEN_FILES);}
                retained.Add(process);processes.emplace(entry.th32ProcessID,process);
            } else CloseHandle(process);
        }while(Process32NextW(snapshot,&entry));
        if(GetLastError()!=ERROR_NO_MORE_FILES)return FolderFailure(error,root,GetLastError());
        bool running=false;
        for(const auto& pair:processes)if(IsProcessStillRunning(pair.second)){running=true;break;}
        if(!running)return true;
        // v7 marked a PID as "asked" even if it did not have a window yet.
        // Enumerate on EVERY pass, recording successful requests per HWND instead.
        for(auto it=posted.begin();it!=posted.end();) {
            HWND window=reinterpret_cast<HWND>(it->second);DWORD pid=0;
            if(!IsWindow(window)||!GetWindowThreadProcessId(window,&pid)||pid!=it->first)it=posted.erase(it);
            else ++it;
        }
        FolderCloseContext context{&processes,&posted};
        EnumWindows(CloseFolderProcessWindow,reinterpret_cast<LPARAM>(&context));
        if(context.requests)(void)0;
        if(context.denied) {
            error=L"Windows не разрешила закрыть окно приложения с более высокими правами (возможно, FTK Imager). Закройте его вручную либо запустите HolyCheck с такими же правами через обычный UAC. Папка не удалялась.";
            return false;
        }
        if(GetTickCount64()>=deadline) {
            error=L"Папка не удалена: приложения ещё работают. Завершите FTK/другие приложения и ответьте на их диалоги сохранения. Принудительное завершение не выполнялось.";
            (void)0;return false;
        }
        SetCleanupWaiting(true);Sleep(500);
    }
}
static void RemoveHolyCheckFolder(DeleteAllMessage& result) {
    if(!IsOwnHolyCheckDirectory(g_appDir)) {
        result.localOk=false;result.localError=L"Удаление заблокировано: разрешена только системная папка Загрузки\\HolyCheck.";return;
    }
    {
        // Reject an aliased root before even requesting that apps close.
        HandleSet pathLocks;
        if(!LockDirectoryChain(g_appDir,pathLocks)) {
            const auto code=GetLastError();
            if(code==ERROR_FILE_NOT_FOUND||code==ERROR_PATH_NOT_FOUND)return;
            result.localOk=FolderFailure(result.localError,g_appDir,code);return;
        }
        result.folderExisted=true;
        wchar_t image[32768]{};const DWORD n=GetModuleFileNameW(nullptr,image,ARRAYSIZE(image));
        if(!n||n>=ARRAYSIZE(image)||HolyFiles::StrictChild(std::wstring(image,n),g_appDir)) {
            result.localOk=false;result.localError=L"HolyCheck.exe запущен из удаляемой папки. Перенесите сам HolyCheck.exe за пределы Загрузки\\HolyCheck, запустите оттуда и повторите. Самоудаление не выполняется.";return;
        }
        if(!CloseFolderProgramsAndWait(g_appDir,result.localError)){result.localOk=false;return;}
    }
    FolderDeletePlan plan;
    // Identity guard also covers 8.3/hardlink aliases of this executable.
    wchar_t image[32768]{};const DWORD n=GetModuleFileNameW(nullptr,image,ARRAYSIZE(image));
    HANDLE self=(n&&n<ARRAYSIZE(image))?CreateFileW(image,FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,0,nullptr):INVALID_HANDLE_VALUE;
    if(self==INVALID_HANDLE_VALUE){result.localOk=FolderFailure(result.localError,L"HolyCheck.exe",GetLastError());return;}
    plan.protectImage=GetFileInformationByHandle(self,&plan.protectedImage)!=FALSE;
    const auto identityError=GetLastError();CloseHandle(self);
    if(!plan.protectImage){result.localOk=FolderFailure(result.localError,L"HolyCheck.exe",identityError);return;}
    // Preflight EVERY node before any mutation; keep handles/parents pinned.
    if(!BuildFolderDeletePlan(g_appDir,plan,result.localError)||!FolderResourcesIdle(plan,result.localError)||
       !CommitFolderDeletePlan(plan,result.localError)){result.localOk=false;return;}
    result.folderRemoved=true;
    for(int i=0;i<static_cast<int>(kItemCount);++i)ClearCachedLaunchPath(i);
    {std::lock_guard<std::mutex> guard(g_extractedMutex);
     for(auto& files:g_extractedFiles)files.clear();
     for(auto& hash:g_inventoryArchiveHash)hash.clear();}
}
// Use validated native vendor uninstallers; never recursively erase their
// installed directories as a fallback for a failed/declined wizard.
static void RemoveInstalledProductsThenFolder(DeleteAllMessage& result) {
    if(!IsOwnHolyCheckDirectory(g_appDir)) {
        result.localOk=false;result.localError=L"Удаление заблокировано: неверная папка HolyCheck.";return;
    }
    std::wstring closeError;
    if(!CloseFolderProgramsAndWait(g_appDir,closeError)) {
        (void)0;
        if(g_cancelRequested.load()){result.localOk=false;result.localSkipped=true;return;}
        // A vendor may close its own app. A failed close is not success, but
        // must not prevent the other independently validated vendor wizards.
    }
    struct Product {const wchar_t* label;InstalledProductDisplayMatcher matcher;std::wstring (*find)();};
    const Product products[]={
        {L"System Informer",SystemInformerDisplayName,FindInstalledSystemInformerPath},
        {L"Process Hacker",ProcessHackerDisplayName,FindInstalledProcessHackerPath},
        {L"FTK Imager",FtkImagerDisplayName,FindInstalledFtkImagerPath},
        {L"Recuva",RecuvaDisplayName,FindInstalledRecuvaPath}
    };
    const bool complete=HolyUninstall::ForEachProduct(ARRAYSIZE(products),
        [] {return g_cancelRequested.load();},[&](unsigned index) {
        const auto& product=products[index];
        bool readable=true;const bool registered=HasRegisteredProduct(product.matcher,readable);
        const auto installed=product.find();
        if(readable&&!registered&&installed.empty())return true;
        ProductRemovalReport report;report.name=product.label;
        if(!readable)report.error=L"Не удалось прочитать состояние регистрации. Удаление не подтверждено.";
        else report.ok=LaunchRegisteredProductUninstallerNoWait(product.label,product.matcher,installed,report.error);
        (void)0;
        if(!report.ok) {
            if(!result.localError.empty())result.localError+=L"\n\n";
            result.localError+=report.name+L": "+report.error;
        }
        const bool ok=report.ok;result.products.push_back(std::move(report));return ok;
    });
    if(g_cancelRequested.load()){result.localOk=false;result.localSkipped=true;return;}
    if(!complete) {
        result.localOk=false;
        result.localError+=L"\n\nПапка HolyCheck сохранена: удаление установленных программ подтверждено не полностью.";return;
    }
    RemoveHolyCheckFolder(result);
}
void DeleteAllDownloaded() {
    if(g_closeWhenIdle||g_cancelRequested.load())return;
    if(!TryBeginDeleteAll()){MessageBoxW(g_mainWindow,L"Сначала дождитесь завершения текущих загрузок или распаковки.",L"HolyCheck",MB_OK|MB_ICONINFORMATION);return;}
    (void)0;HWND target=g_mainWindow;
    StartWorker(-1,[target] {
        const HRESULT hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
        struct ComScope{HRESULT hr;~ComScope(){if(SUCCEEDED(hr))CoUninitialize();}} com{hr};
        auto result=std::make_unique<DeleteAllMessage>();
        RemoveInstalledProductsThenFolder(*result);
        if(g_cancelRequested.load()){result->localOk=false;result->localSkipped=true;}
        (void)0;
        if(!PostDeleteAllResult(target,std::move(result)))g_deleteAllBusy.store(false);
    });
}
