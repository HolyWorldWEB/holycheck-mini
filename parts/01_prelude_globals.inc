constexpr wchar_t kWindowClass[] = L"HolyCheckWindow";
constexpr wchar_t kWindowTitle[] = L"HolyCheck";

constexpr UINT WM_APP_DOWNLOAD_STARTED = WM_APP + 8;
constexpr UINT WM_APP_DOWNLOAD_DONE = WM_APP + 1;
constexpr UINT WM_APP_DOWNLOAD_PROGRESS = WM_APP + 2;
constexpr UINT WM_APP_OPEN_READY = WM_APP + 3;
constexpr UINT WM_APP_DELETE_ALL_DONE = WM_APP + 4;
constexpr UINT TIMER_PARTICLES = 1; // fallback only
constexpr UINT TIMER_MAINTENANCE = 3;
constexpr UINT WM_APP_FRAME = WM_APP + 7;
constexpr UINT WM_APP_UNINSTALL_STATUS = WM_APP + 6;

constexpr int IDI_HOLYCHECK = 101;
constexpr int IDC_DELETE_ALL = 1100;
constexpr int IDC_DOWNLOAD_ALL = 1101;
constexpr int IDC_CANCEL_ALL = 1102;
constexpr int IDC_TAB_BASE = 2000;
constexpr int IDC_TILE_BASE = 3000;

constexpr int TAB_COUNT = 5;
constexpr COLORREF BG = RGB(18, 18, 19);
constexpr COLORREF TEXT = RGB(228, 229, 233);

static HolyLog::Async g_fullLog;
static std::atomic<DWORD> g_fullLogError{ERROR_SUCCESS};
static void FullLog(const std::wstring& text) noexcept {
    try {
        SYSTEMTIME t{}; GetSystemTime(&t); wchar_t stamp[100]{};
        swprintf_s(stamp, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ tid=%lu ",
            t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond,t.wMilliseconds,GetCurrentThreadId());
        g_fullLog.Submit(std::wstring(stamp) + text);
    } catch (...) { g_fullLogError.store(ERROR_NOT_ENOUGH_MEMORY); }
}
struct DownloadItem {
    const wchar_t* name;
    const wchar_t* url;
    const wchar_t* file;
    int tab;
    // SHA-256 of the exact downloadable payload. In release builds this is
    // fail-closed: items without a pin are not downloaded or launched.
    const wchar_t* sha256 = nullptr;
    bool rolling = false; // Only unversioned upstream URLs use signed updates.
    bool website = false; // Explicit fixed browser actions, never downloaded/installed.
};

constexpr DownloadItem kItems[] = {
    { L"Everything",              L"https://www.voidtools.com/Everything-1.5.0.1404a.x64.zip", L"Everything-1.5.0.1404a.x64.zip", 0, L"41a372703ef26dead7fd5245fa708791e5bb72c3532c0a44995324c6b54ee198" },
    { L"ShellBag Analyzer",       L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/shellbag_analyzer_cleaner.exe", L"shellbag_analyzer_cleaner.exe", 0, L"bfa1529853f88ac0770bcfcf035265b8dff4cbd4ca865f657095bccadd6aba5f" },
    { L"RecentFilesView",         L"https://www.nirsoft.net/utils/recentfilesview.zip", L"recentfilesview.zip", 0, L"6920cc0165fcffa1a009c663c3dce7c84a62ca0e4b73d9d86dc9cc0dc39dca61", true },
    { L"SystemInformer",          L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/systeminformer-build-canary-setup.exe", L"systeminformer-build-canary-setup.exe", 0, L"7612d5e44a5a392ab9f0d1b5b8a79bda3cdbe19848e8ee9ec23909aaf3daad45" },
    { L"LastActivityView",        L"https://www.nirsoft.net/utils/lastactivityview.zip", L"lastactivityview.zip", 0, L"09976fd76ae40a608f424655cda82b2be77c426c88ea95af78378b47630397bf", true },
    { L"ExecutedProgramsList",    L"https://www.nirsoft.net/utils/executedprogramslist.zip", L"executedprogramslist.zip", 0, L"359f4b27c4bca018e51cc3ceca5c3ae8f70c004f384949ad24822ecf5cefbf40", true },
    { L"RegScanner",              L"https://www.nirsoft.net/utils/regscanner.zip", L"regscanner.zip", 0, L"fe93d9534c634523c499c55590bf6bb4466624b975f3052606de38969e357b2d", true },
    { L"ProcessHacker",           L"https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe", L"processhacker-2.39-setup.exe", 3, L"28042dd4a92a0033b8f1d419b9e989c5b8e32d1d2d881f5c8251d58ce35b9063" },
    { L"BrowserDownloadsView",    L"https://www.nirsoft.net/utils/browserdownloadsview.zip", L"browserdownloadsview.zip", 0, L"60e95026983e128a81f7c7ed11fe7e94373ce4604216fd879f7d340cf8844d3a", true },
    { L"MinecraftVersionChecker", L"https://github.com/HolyWorldWEB/VersionChecker/releases/download/v1.0.0/MinecraftVersionChecker.exe", L"MinecraftVersionChecker.exe", 0, L"1a23e875d4429e38a7070492267ee21676bcc843eba13ae90feea5182ba9cc9c" },
    { L"USBDriveLog",             L"https://www.nirsoft.net/utils/usbdrivelog.zip", L"usbdrivelog.zip", 0, L"098d9af885a4651f26a3d50395637418c118866200b96bdbcbf048b30aaf6bbb", true },
    { L"USBDeview",               L"https://www.nirsoft.net/utils/usbdeview-x64.zip", L"usbdeview-x64.zip", 3, L"7eb383f7fbdde8b48ecba07cd97adda515e8ffc04839b0427cc89ced893c161b", true },
    { L"JournalTrace",            L"https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe", L"JournalTrace.exe", 0, L"8fb81630da2eb82f8c9b4a8eaaff5bbeb3257d9e0bf7af44c6b16b50e98150e3" },
    { L"WinRAR",                  L"https://www.rarlab.com/rar/winrar-x64-722ru.exe", L"winrar-x64-722ru.exe", 3, L"0f1a5efdf15fac39a0e6b52b5c3c7accbc2647f3a1eed8459db89302169797d0" },

    { L"BAMParser",               L"https://github.com/spokwn/BAM-parser/releases/download/v1.2.8/BAMParser.exe", L"BAMParser.exe", 1, L"5f061ebafbe7a87b7c01f4ddf24eded23d475ceae710379c4c76fcb228f3e7a2" },
    { L"RegistryExplorer",        L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/RegistryExplorer.zip", L"RegistryExplorer.zip", 1, L"7cbd0994c0329b24a95cb7e66354d959f0e3fbf5ee9811b63a7d3d898be4f4f2" },
    { L"JumpListExplorer",        L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/JumpListExplorer.zip", L"JumpListExplorer.zip", 1, L"953c2d91c948e48f1f0731817033bd89b877f8dd163720d8c1d686ac6214d737" },
    { L"SimpleUnlocker",          L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/simpleunlocker_release.zip", L"simpleunlocker_release.zip", 1, L"9768bf823d8f801913705dca9032b83b6912061c3a7b4bb7f47c9f225651d78f" },
    { L"WinPrefetchView",         L"https://www.nirsoft.net/utils/winprefetchview.zip", L"winprefetchview.zip", 1, L"7c7c7cfbf74026e8679d5c866717d7bfd2df9f875ed17c210068df1aa7380bc6", true },
    { L"Recuva",                  L"https://download.ccleaner.com/rcsetup155.exe", L"rcsetup155.exe", 1, L"6440c5e69e01da6ec4345a7264145d65221a139a46c13e26a21ad18b04663244" },

    { L"PathsParser",             L"https://github.com/spokwn/PathsParser/releases/download/v1.1/PathsParser.exe", L"PathsParser.exe", 2, L"88a721c1ce2a34129fa1c536b8eb2f99bb81ead1f3613c122a15ec79cd44a4ca" },
    { L"Detect It Easy",          L"https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip", L"die_win64_portable_3.10_x64.zip", 2, L"6e84ac8d3abdfba60078a36fa7f6b492b20c2af2c502e0a4579f41367ac37c80" },
    { L"Recaf CLI",               L"https://github.com/Col-E/Recaf-Launcher/releases/download/0.8.8/recaf-cli-0.8.8.jar", L"recaf-cli-0.8.8.jar", 2, L"600b911b9c5d2f150598bea69316e656428c500fd49db8d7edae67eb79149fce" },

    { L"BrowsingHistoryView",     L"https://www.nirsoft.net/utils/browsinghistoryview.zip", L"browsinghistoryview.zip", 3, L"f3ecc6a7028b57bbe7b3a15d32bc89a311c7d77fd8fe0563f0f70ec200d7e5a6", true },
    { L"AlternateStreamView",     L"https://www.nirsoft.net/utils/alternatestreamview-x64.zip", L"alternatestreamview-x64.zip", 4, L"ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d", true },
    { L"WinDefLogView",           L"https://www.nirsoft.net/utils/windeflogview.zip", L"windeflogview.zip", 3, L"235c17c453e96182a72ee957b40c567bc7bef2d466b8b7302d38e79cf1f3d219", true },
    { L"VolatilityWorkbench",     L"https://www.osforensics.com/downloads/VolatilityWorkbench.zip", L"VolatilityWorkbench.zip", 4, L"61474fd9e85444c339dcfd38eb5060eaab71b32245e8a2a477d6c4b303d738a3", true },
    { L"KernelLiveDumpTool",      L"https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe", L"KernelLiveDumpTool.exe", 4, L"b28ea771595d1a020ca04af2bed7008b9e6a65bb23ac9fe385aaa3341b21af9e" },
    { L"FTK Imager",              L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/FTK.Imager.8.3.0.27.zip", L"FTK.Imager.8.3.0.27.zip", 4, L"0f717d0d91c94af94107775ae37c2e330cc2a2312a8eecc91a344c8010e82afe" },
    { L"MRC", L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/MRCv120.exe", L"MRCv120.exe", 4, L"72dc1ba6ddc9d572d70a194ebdf6027039734ecee23a02751b0b3b3c4ea430de" },
    // Information/release pages only: never fetch or launch their EXE assets.
    { L"PrefetchView++", L"https://github.com/Orbdiff/PrefetchView/releases/tag/v1.5.3", L"", 4, nullptr, false, true },
    { L"RedLotusAltChecker", L"https://github.com/ItzIceHere/RedLotusAltChecker/releases/latest", L"", 4, nullptr, false, true },
    { L"UserAssistView", L"https://www.nirsoft.net/utils/userassistview.zip", L"userassistview.zip", 4, L"11b75025ac99ad31fa2c27b91ebbdb891fced36ff8b2567b0b76146af88d57d9", true },
    { L"detect.ac", L"https://detect.ac/tools", L"", 4, nullptr, false, true },
    { L"Eric Zimerman Tools", L"https://ericzimmerman.github.io/#forensic-tools", L"", 4, nullptr, false, true }
};

constexpr size_t kItemCount = sizeof(kItems) / sizeof(kItems[0]);
constexpr const wchar_t* kTabs[TAB_COUNT] = {
    L"Мл.сотрудник", L"Сотрудник", L"Вед.сотрудник", L"Доп.программы", L"ss"
};

struct DownloadMessage {
    int itemIndex = -1;
    bool ok = false;
    bool openAfterDownload = true;
    std::wstring text;
    bool downloaded = false;
    bool launched = false;
    bool showError = true;
};

struct OpenReadyMessage {
    int itemIndex = -1;
    bool ok = false;
    std::wstring path;
    std::wstring error;
};

struct ProductRemovalReport { std::wstring name,error; bool ok=false; };
struct DeleteAllMessage {
    std::vector<ProductRemovalReport> products;
    bool localOk = true;
    bool localSkipped = false;
    bool folderExisted = false;
    bool folderRemoved = false;
    std::wstring localError;
};

struct ApprovedLaunchTarget {
    std::wstring path;
    BY_HANDLE_FILE_INFORMATION identity{};
    bool valid=false;
};
// Keep the verified target after a launcher exits/single-instance handoff.
std::array<ApprovedLaunchTarget,kItemCount> g_approvedLaunchTargets;

struct LaunchedProcess {
    int itemIndex = -1;
    HANDLE process = nullptr;
    DWORD pid = 0;
    std::wstring path; // Installed app and its installer are distinct targets.
};

struct Particle { float x = 0, y = 0, vx = 0, vy = 0, size = 1; BYTE alpha = 40; };
struct Star { float x = 0, y = 0, size = 1, phase = 0, speed = 1; BYTE alpha = 40; };
struct Comet { float x = 0, y = 0, vx = 0, vy = 0, life = 0, maxLife = 0; };

HINSTANCE g_instance = nullptr;
HWND g_mainWindow = nullptr;
HWND g_deleteAll = nullptr;
HWND g_downloadAll = nullptr;
HWND g_cancelAll = nullptr;
bool g_keyboardNavigation = false; // UI thread only; mouse clicks must leave no focus trail.
std::atomic<int> g_uninstallItem{-1};
std::atomic<bool> g_uninstallWaiting{false};
std::atomic<bool> g_cleanupWaiting{false};
bool g_cancelUiActive = false; // UI thread only
std::vector<HWND> g_tabButtons;
std::vector<HWND> g_tileButtons;
HFONT g_font = nullptr;
HFONT g_smallFont = nullptr;
HFONT g_compactSiteFont = nullptr; // Cached 11px two-line website caption.
ULONG_PTR g_gdiplusToken = 0;

std::wstring g_appDir;
// Payloads live in the five tab directories; each ZIP extracts into its own sibling folder.
std::array<std::recursive_mutex, TAB_COUNT> g_tabFileMutex;
int g_currentTab = 0;
std::array<std::atomic<int>, kItemCount> g_itemProgress{};
std::atomic<bool> g_deleteAllBusy{false};
std::atomic<bool> g_cancelRequested{false};
bool g_closeWhenIdle = false; // UI thread only
std::mutex g_busyMutex;
std::set<int> g_busyItems;
std::mutex g_logMutex;
using DownloadLogLine=HolyUi::DownloadLogLine;
std::deque<DownloadLogLine> g_logLines;
HolyUi::LogViewport g_logViewport; // Protected by g_logMutex, like the rows.
std::vector<Particle> g_particles;
std::vector<Star> g_staticStars;
std::vector<Comet> g_comets;
std::mutex g_processMutex;
std::vector<LaunchedProcess> g_launchedProcesses;

// Worker threads never pass heap pointers through WM_APP messages. Results are
// stored here and the UI message carries only a validated item index. This
// prevents another process/window from crashing HolyCheck with a forged lParam.
std::mutex g_asyncResultMutex;
std::array<std::unique_ptr<DownloadMessage>, kItemCount> g_pendingDownloadResults{};
std::array<std::unique_ptr<OpenReadyMessage>, kItemCount> g_pendingOpenReadyResults{};
std::unique_ptr<DeleteAllMessage> g_pendingDeleteAllResult;

ULONGLONG g_lastCometSpawn = 0;
bool g_particlesPaused = false;

bool BasicPayloadCheck(const std::wstring& path,const std::wstring& fileName,HANDLE alreadyOpen=INVALID_HANDLE_VALUE);
void LayoutControls(HWND hwnd);
void RefreshItemButtons(int itemIndex);
static bool IsSha256(const std::wstring& pin) {
    if (pin.size() != 64) return false;
    for (size_t i = 0; i < 64; ++i) {
        const wchar_t ch = pin[i];
        const bool hex = (ch >= L'0' && ch <= L'9') ||
                         (ch >= L'a' && ch <= L'f') ||
                         (ch >= L'A' && ch <= L'F');
        if (!hex) return false;
    }
    return true;
}

// Trust changes are reviewed at build time, never loaded beside the executable.
static const std::array<std::wstring, kItemCount>& PayloadPins() {
    static const auto pins = [] {
        std::array<std::wstring, kItemCount> result{};
        for (size_t i = 0; i < kItemCount; ++i)
            if (kItems[i].sha256) result[i] = kItems[i].sha256;
        return result;
    }();
    return pins;
}

// Created only by the UI thread; joined before global/UI resources are released.
static std::unique_ptr<HolyWorkers::Pool> g_workers;
static void JoinWorkers() {
    if (g_workers) { g_workers->Stop(); g_workers.reset(); }
}

static bool HasPinnedSha256(int itemIndex) {
    return itemIndex >= 0 && static_cast<size_t>(itemIndex) < kItemCount &&
           IsSha256(PayloadPins()[itemIndex]);
}

static bool IsReportedUnsafePayload(int itemIndex) {
    return itemIndex>=0&&static_cast<size_t>(itemIndex)<kItemCount&&
        HolyFiles::ReportedUnsafePayloadSha256(PayloadPins()[static_cast<size_t>(itemIndex)]);
}
static bool RejectReportedPayload(int itemIndex,std::wstring& error) {
    if(!IsReportedUnsafePayload(itemIndex))return false;
    error=std::wstring(kItems[itemIndex].name)+
        L": эта версия заблокирована в HolyCheck после обнаружения Kaspersky. "
        L"Скачивание и запуск отключены до проверки разработчиком и антивирусной лабораторией. "
        L"Не восстанавливайте файл из карантина и не добавляйте исключение.";
    return true;
}

static bool PostDownloadResult(HWND target, std::unique_ptr<DownloadMessage> result) {
    if (!result || result->itemIndex < 0 || static_cast<size_t>(result->itemIndex) >= kItemCount)
        return false;
    const int itemIndex = result->itemIndex;
    {
        std::lock_guard<std::mutex> lock(g_asyncResultMutex);
        if (g_pendingDownloadResults[static_cast<size_t>(itemIndex)]) return false;
        g_pendingDownloadResults[static_cast<size_t>(itemIndex)] = std::move(result);
    }
    if (PostMessageW(target, WM_APP_DOWNLOAD_DONE, static_cast<WPARAM>(itemIndex), 0)) return true;
    std::lock_guard<std::mutex> lock(g_asyncResultMutex);
    g_pendingDownloadResults[static_cast<size_t>(itemIndex)].reset();
    return false;
}

static std::unique_ptr<DownloadMessage> TakeDownloadResult(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return {};
    std::lock_guard<std::mutex> lock(g_asyncResultMutex);
    return std::move(g_pendingDownloadResults[static_cast<size_t>(itemIndex)]);
}

[[maybe_unused]] static bool PostOpenReadyResult(HWND target, std::unique_ptr<OpenReadyMessage> result) {
    if (!result || result->itemIndex < 0 || static_cast<size_t>(result->itemIndex) >= kItemCount)
        return false;
    const int itemIndex = result->itemIndex;
    {
        std::lock_guard<std::mutex> lock(g_asyncResultMutex);
        if (g_pendingOpenReadyResults[static_cast<size_t>(itemIndex)]) return false;
        g_pendingOpenReadyResults[static_cast<size_t>(itemIndex)] = std::move(result);
    }
    if (PostMessageW(target, WM_APP_OPEN_READY, static_cast<WPARAM>(itemIndex), 0)) return true;
    std::lock_guard<std::mutex> lock(g_asyncResultMutex);
    g_pendingOpenReadyResults[static_cast<size_t>(itemIndex)].reset();
    return false;
}

static std::unique_ptr<OpenReadyMessage> TakeOpenReadyResult(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return {};
    std::lock_guard<std::mutex> lock(g_asyncResultMutex);
    return std::move(g_pendingOpenReadyResults[static_cast<size_t>(itemIndex)]);
}

static bool PostDeleteAllResult(HWND target, std::unique_ptr<DeleteAllMessage> result) {
    if (!result) return false;
    {
        std::lock_guard<std::mutex> lock(g_asyncResultMutex);
        if (g_pendingDeleteAllResult) return false;
        g_pendingDeleteAllResult = std::move(result);
    }
    if (PostMessageW(target, WM_APP_DELETE_ALL_DONE, 0, 0)) return true;
    std::lock_guard<std::mutex> lock(g_asyncResultMutex);
    g_pendingDeleteAllResult.reset();
    return false;
}

static std::unique_ptr<DeleteAllMessage> TakeDeleteAllResult() {
    std::lock_guard<std::mutex> lock(g_asyncResultMutex);
    return std::move(g_pendingDeleteAllResult);
}

void MarkIdle(int itemIndex);

template<class Work>
static void StartWorker(int itemIndex, Work work, bool interactive = false) {
    try {
        if (!g_workers) g_workers = std::make_unique<HolyWorkers::Pool>(4);
        const bool queued = g_workers->Submit([itemIndex, work = std::move(work)]() {
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
            FullLog(L"WORK start item=" + std::to_wstring(itemIndex));
            try { work(); FullLog(L"WORK return item=" + std::to_wstring(itemIndex)); }
            catch (...) {
                FullLog(L"WORK exception item=" + std::to_wstring(itemIndex));
                // No exception may escape a std::thread and terminate the UI.
                try {
                    if (itemIndex >= 0) {
                        auto result = std::make_unique<DownloadMessage>();
                        result->itemIndex = itemIndex;
                        result->openAfterDownload = false;
                        result->text = L"Внутренняя ошибка операции. Файл не будет открыт.";
                        if (!PostDownloadResult(g_mainWindow, std::move(result))) MarkIdle(itemIndex);
                    } else {
                        auto result = std::make_unique<DeleteAllMessage>();
                        result->localOk = false;
                        if (!PostDeleteAllResult(g_mainWindow, std::move(result))) g_deleteAllBusy.store(false);
                    }
                } catch (...) {
                    if (itemIndex >= 0) MarkIdle(itemIndex);
                    else g_deleteAllBusy.store(false);
                }
            }
        }, interactive);
        FullLog(L"WORK queued=" + std::to_wstring(queued) + L" item=" + std::to_wstring(itemIndex));
        if (!queued) throw std::runtime_error("worker queue full");
    } catch (...) {
        if (itemIndex >= 0) MarkIdle(itemIndex);
        else g_deleteAllBusy.store(false);
        if (itemIndex >= 0) RefreshItemButtons(itemIndex);
        MessageBoxW(g_mainWindow, L"Не удалось поставить операцию в ограниченную очередь.", L"HolyCheck", MB_OK | MB_ICONERROR);
    }
}

static void RemoveDownloadStatus(int itemIndex) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if(HolyUi::RemoveDownloadRows(g_logLines,g_logViewport,itemIndex)&&g_mainWindow)
        InvalidateRect(g_mainWindow,nullptr,FALSE);
}
static void AddLog(const std::wstring& text,int itemIndex=-1,bool folderIcon=false,bool downloading=false) {
    FullLog(L"UI_LOG " + text);
    std::lock_guard<std::mutex> lock(g_logMutex);
    if(itemIndex<0||static_cast<size_t>(itemIndex)>=kItemCount)itemIndex=-1;
    if(itemIndex>=0)HolyUi::RemoveDownloadRows(g_logLines,g_logViewport,itemIndex);
    else downloading=false;
    g_logLines.push_back({text,itemIndex,folderIcon,downloading});
    while (g_logLines.size() > 100) g_logLines.pop_front();
    g_logViewport.Appended(g_logLines.size());
    if (g_mainWindow) InvalidateRect(g_mainWindow, nullptr, FALSE);
}
