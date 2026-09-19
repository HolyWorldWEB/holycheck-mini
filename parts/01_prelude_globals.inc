constexpr wchar_t kWindowClass[] = L"HolyCheckWindow";
constexpr wchar_t kWindowTitle[] = L"HolyCheck";

constexpr UINT WM_APP_DOWNLOAD_DONE = WM_APP + 1;
constexpr UINT WM_APP_DOWNLOAD_PROGRESS = WM_APP + 2;
constexpr UINT WM_APP_OPEN_READY = WM_APP + 3;
constexpr UINT WM_APP_DELETE_ALL_DONE = WM_APP + 4;
constexpr UINT TIMER_PARTICLES = 1;

constexpr int IDC_DELETE_ALL = 1100;
constexpr int IDC_DOWNLOAD_ALL = 1101;
constexpr int IDC_TAB_BASE = 2000;
constexpr int IDC_TILE_BASE = 3000;

constexpr int TAB_COUNT = 4;
constexpr COLORREF BG = RGB(18, 18, 19);
constexpr COLORREF TEXT = RGB(228, 229, 233);

struct DownloadItem {
    const wchar_t* name;
    const wchar_t* url;
    const wchar_t* file;
    int tab;
    // SHA-256 of the exact downloadable payload. In release builds this is
    // fail-closed: items without a pin are not downloaded or launched.
    const wchar_t* sha256 = nullptr;
};

constexpr DownloadItem kItems[] = {
    { L"Everything",              L"https://www.voidtools.com/Everything-1.5.0.1404a.x64.zip", L"Everything-1.5.0.1404a.x64.zip", 0, L"41a372703ef26dead7fd5245fa708791e5bb72c3532c0a44995324c6b54ee198" },
    { L"ShellBag Analyzer",       L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/shellbag_analyzer_cleaner.exe", L"shellbag_analyzer_cleaner.exe", 0, L"bfa1529853f88ac0770bcfcf035265b8dff4cbd4ca865f657095bccadd6aba5f" },
    { L"RecentFilesView",         L"https://www.nirsoft.net/utils/recentfilesview.zip", L"recentfilesview.zip", 0, L"6920cc0165fcffa1a009c663c3dce7c84a62ca0e4b73d9d86dc9cc0dc39dca61" },
    { L"SystemInformer",          L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/systeminformer-build-canary-setup.exe", L"systeminformer-build-canary-setup.exe", 0, L"7612d5e44a5a392ab9f0d1b5b8a79bda3cdbe19848e8ee9ec23909aaf3daad45" },
    { L"LastActivityView",        L"https://www.nirsoft.net/utils/lastactivityview.zip", L"lastactivityview.zip", 0, L"09976fd76ae40a608f424655cda82b2be77c426c88ea95af78378b47630397bf" },
    { L"ExecutedProgramsList",    L"https://www.nirsoft.net/utils/executedprogramslist.zip", L"executedprogramslist.zip", 0, L"359f4b27c4bca018e51cc3ceca5c3ae8f70c004f384949ad24822ecf5cefbf40" },
    { L"RegScanner",              L"https://www.nirsoft.net/utils/regscanner.zip", L"regscanner.zip", 0, L"fe93d9534c634523c499c55590bf6bb4466624b975f3052606de38969e357b2d" },
    { L"ProcessHacker",           L"https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe", L"processhacker-2.39-setup.exe", 3, L"28042dd4a92a0033b8f1d419b9e989c5b8e32d1d2d881f5c8251d58ce35b9063" },
    { L"BrowserDownloadsView",    L"https://www.nirsoft.net/utils/browserdownloadsview.zip", L"browserdownloadsview.zip", 0, L"60e95026983e128a81f7c7ed11fe7e94373ce4604216fd879f7d340cf8844d3a" },
    { L"MinecraftVersionChecker", L"https://github.com/HolyWorldWEB/VersionChecker/releases/download/v1.0.0/MinecraftVersionChecker.exe", L"MinecraftVersionChecker.exe", 0, L"1a23e875d4429e38a7070492267ee21676bcc843eba13ae90feea5182ba9cc9c" },
    { L"USBDriveLog",             L"https://www.nirsoft.net/utils/usbdrivelog.zip", L"usbdrivelog.zip", 0, L"098d9af885a4651f26a3d50395637418c118866200b96bdbcbf048b30aaf6bbb" },
    { L"USBDeview",               L"https://www.nirsoft.net/utils/usbdeview-x64.zip", L"usbdeview-x64.zip", 3, L"7eb383f7fbdde8b48ecba07cd97adda515e8ffc04839b0427cc89ced893c161b" },
    { L"JournalTrace",            L"https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTraceNormal.exe", L"JournalTraceNormal.exe", 0, L"6cfd501925026f38bb97503df6211cd042e6f8b7f4e4e72457b098eb573ff775" },
    { L"WinRAR",                  L"https://www.rarlab.com/rar/winrar-x64-722ru.exe", L"winrar-x64-722ru.exe", 3, L"0f1a5efdf15fac39a0e6b52b5c3c7accbc2647f3a1eed8459db89302169797d0" },

    { L"BAMParser",               L"https://github.com/spokwn/BAM-parser/releases/download/v1.2.8/BAMParser.exe", L"BAMParser.exe", 1, L"5f061ebafbe7a87b7c01f4ddf24eded23d475ceae710379c4c76fcb228f3e7a2" },
    { L"RegistryExplorer",        L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/RegistryExplorer.zip", L"RegistryExplorer.zip", 1, L"7cbd0994c0329b24a95cb7e66354d959f0e3fbf5ee9811b63a7d3d898be4f4f2" },
    { L"JumpListExplorer",        L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/JumpListExplorer.zip", L"JumpListExplorer.zip", 1, L"953c2d91c948e48f1f0731817033bd89b877f8dd163720d8c1d686ac6214d737" },
    { L"SimpleUnlocker",          L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/simpleunlocker_release.zip", L"simpleunlocker_release.zip", 1, L"9768bf823d8f801913705dca9032b83b6912061c3a7b4bb7f47c9f225651d78f" },
    { L"WinPrefetchView",         L"https://www.nirsoft.net/utils/winprefetchview.zip", L"winprefetchview.zip", 1, L"7c7c7cfbf74026e8679d5c866717d7bfd2df9f875ed17c210068df1aa7380bc6" },
    { L"Recuva",                  L"https://download.ccleaner.com/rcsetup155.exe", L"rcsetup155.exe", 1, L"6440c5e69e01da6ec4345a7264145d65221a139a46c13e26a21ad18b04663244" },

    { L"PathsParser",             L"https://github.com/spokwn/PathsParser/releases/download/v1.1/PathsParser.exe", L"PathsParser.exe", 2, L"88a721c1ce2a34129fa1c536b8eb2f99bb81ead1f3613c122a15ec79cd44a4ca" },
    { L"Detect It Easy",          L"https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip", L"die_win64_portable_3.10_x64.zip", 2, L"6e84ac8d3abdfba60078a36fa7f6b492b20c2af2c502e0a4579f41367ac37c80" },
    { L"Recaf CLI",               L"https://github.com/Col-E/Recaf-Launcher/releases/download/0.8.8/recaf-cli-0.8.8.jar", L"recaf-cli-0.8.8.jar", 2, L"600b911b9c5d2f150598bea69316e656428c500fd49db8d7edae67eb79149fce" },

    { L"BrowsingHistoryView",     L"https://www.nirsoft.net/utils/browsinghistoryview.zip", L"browsinghistoryview.zip", 3, L"f3ecc6a7028b57bbe7b3a15d32bc89a311c7d77fd8fe0563f0f70ec200d7e5a6" },
    { L"AlternateStreamView",     L"https://www.nirsoft.net/utils/alternatestreamview-x64.zip", L"alternatestreamview-x64.zip", 3, L"ad1f0edb2202ec1a736d9266b18b241eac5542c350578a3a8cdb4dd8b14ff37d" },
    { L"WinDefLogView",           L"https://www.nirsoft.net/utils/windeflogview.zip", L"windeflogview.zip", 3, L"235c17c453e96182a72ee957b40c567bc7bef2d466b8b7302d38e79cf1f3d219" },
    { L"VolatilityWorkbench",     L"https://www.osforensics.com/downloads/VolatilityWorkbench.zip", L"VolatilityWorkbench.zip", 3, L"604e2eba56736c24b5265842cc217c8936a66bd2527191cd9262a2aa53cec6a4" },
    { L"KernelLiveDumpTool",      L"https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe", L"KernelLiveDumpTool.exe", 3, L"b28ea771595d1a020ca04af2bed7008b9e6a65bb23ac9fe385aaa3341b21af9e" },
    { L"FTK Imager",              L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/FTK.Imager.8.3.0.27.zip", L"FTK.Imager.8.3.0.27.zip", 3, L"0f717d0d91c94af94107775ae37c2e330cc2a2312a8eecc91a344c8010e82afe" }
};

constexpr size_t kItemCount = sizeof(kItems) / sizeof(kItems[0]);
constexpr const wchar_t* kTabs[TAB_COUNT] = {
    L"Мл.сотрудник", L"Сотрудник", L"Вед.сотрудник", L"Доп.программы"
};

struct DownloadMessage {
    int itemIndex = -1;
    bool ok = false;
    bool openAfterDownload = true;
    std::wstring text;
};

struct OpenReadyMessage {
    int itemIndex = -1;
    bool ok = false;
    std::wstring path;
    std::wstring error;
};

struct DeleteAllMessage {
    bool localOk = true;
    bool systemInformerWasInstalled = false;
    bool recuvaWasInstalled = false;
    bool ftkImagerWasInstalled = false;
    bool systemInformerUninstallStarted = true;
    bool recuvaUninstallStarted = true;
    bool ftkImagerUninstallStarted = true;
    std::wstring systemInformerError;
    std::wstring recuvaError;
    std::wstring ftkImagerError;
    std::vector<int> existingItems;
};

struct LaunchedProcess {
    int itemIndex = -1;
    HANDLE process = nullptr;
    DWORD pid = 0;
};

struct Particle { float x = 0, y = 0, vx = 0, vy = 0, size = 1; BYTE alpha = 40; };
struct Star { float x = 0, y = 0, size = 1, phase = 0, speed = 1; BYTE alpha = 40; };
struct Comet { float x = 0, y = 0, vx = 0, vy = 0, life = 0, maxLife = 0; };

HINSTANCE g_instance = nullptr;
HWND g_mainWindow = nullptr;
HWND g_deleteAll = nullptr;
HWND g_downloadAll = nullptr;
std::vector<HWND> g_tabButtons;
std::vector<HWND> g_tileButtons;
HFONT g_font = nullptr;
HFONT g_smallFont = nullptr;
ULONG_PTR g_gdiplusToken = 0;

std::wstring g_appDir;
std::wstring g_downloadDir;
std::wstring g_extractDir;
int g_currentTab = 0;
std::array<std::atomic<int>, kItemCount> g_itemProgress{};
std::atomic<bool> g_deleteAllBusy{false};
std::mutex g_busyMutex;
std::set<int> g_busyItems;
std::mutex g_logMutex;
std::deque<std::wstring> g_logLines;
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

bool BasicPayloadCheck(const std::wstring& path, const std::wstring& fileName);
void LayoutControls(HWND hwnd);
void RefreshItemButtons(int itemIndex);
static bool DeleteDirectoryTreeNoReparse(const std::wstring& directory);

static bool HasPinnedSha256(int itemIndex) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    const wchar_t* pin = kItems[itemIndex].sha256;
    if (!pin || wcslen(pin) != 64) return false;
    for (size_t i = 0; i < 64; ++i) {
        const wchar_t ch = pin[i];
        const bool hex = (ch >= L'0' && ch <= L'9') ||
                         (ch >= L'a' && ch <= L'f') ||
                         (ch >= L'A' && ch <= L'F');
        if (!hex) return false;
    }
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

static bool PostOpenReadyResult(HWND target, std::unique_ptr<OpenReadyMessage> result) {
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

static void AddLog(const std::wstring& text) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logLines.push_back(text);
    while (g_logLines.size() > 100) g_logLines.pop_front();
    if (g_mainWindow) InvalidateRect(g_mainWindow, nullptr, FALSE);
}
