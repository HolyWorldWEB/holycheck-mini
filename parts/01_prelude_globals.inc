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
};

constexpr DownloadItem kItems[] = {
    { L"Everything",              L"https://www.voidtools.com/Everything-1.5.0.1404a.x64.zip", L"Everything-1.5.0.1404a.x64.zip", 0 },
    { L"ShellBag Analyzer",       L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/shellbag_analyzer_cleaner.exe", L"shellbag_analyzer_cleaner.exe", 0 },
    { L"RecentFilesView",         L"https://www.nirsoft.net/utils/recentfilesview.zip", L"recentfilesview.zip", 0 },
    { L"SystemInformer",          L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/systeminformer-build-canary-setup.exe", L"systeminformer-build-canary-setup.exe", 0 },
    { L"LastActivityView",        L"https://www.nirsoft.net/utils/lastactivityview.zip", L"lastactivityview.zip", 0 },
    { L"ExecutedProgramsList",    L"https://www.nirsoft.net/utils/executedprogramslist.zip", L"executedprogramslist.zip", 0 },
    { L"RegScanner",              L"https://www.nirsoft.net/utils/regscanner.zip", L"regscanner.zip", 0 },
    { L"ProcessHacker",           L"https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe", L"processhacker-2.39-setup.exe", 3 },
    { L"BrowserDownloadsView",    L"https://www.nirsoft.net/utils/browserdownloadsview.zip", L"browserdownloadsview.zip", 0 },
    { L"MinecraftVersionChecker", L"https://github.com/HolyWorldWEB/VersionChecker/releases/download/v1.0.0/MinecraftVersionChecker.exe", L"MinecraftVersionChecker.exe", 0 },
    { L"USBDriveLog",             L"https://www.nirsoft.net/utils/usbdrivelog.zip", L"usbdrivelog.zip", 0 },
    { L"USBDeview",               L"https://usbdeview.com/wp-content/uploads/2025/02/usbdeview-x64.zip", L"usbdeview-x64.zip", 3 },
    { L"JournalTrace",            L"https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe", L"JournalTrace.exe", 0 },
    { L"WinRAR",                  L"https://www.rarlab.com/rar/winrar-x64-722ru.exe", L"winrar-x64-722ru.exe", 3 },

    { L"BAMParser",               L"https://github.com/spokwn/BAM-parser/releases/download/v1.2.8/BAMParser.exe", L"BAMParser.exe", 1 },
    { L"RegistryExplorer",        L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/RegistryExplorer.zip", L"RegistryExplorer.zip", 1 },
    { L"JumpListExplorer",        L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/JumpListExplorer.zip", L"JumpListExplorer.zip", 1 },
    { L"SimpleUnlocker",          L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/simpleunlocker_release.zip", L"simpleunlocker_release.zip", 1 },
    { L"WinPrefetchView",         L"https://www.nirsoft.net/utils/winprefetchview.zip", L"winprefetchview.zip", 1 },
    { L"Recuva",                  L"https://download.ccleaner.com/rcsetup155.exe", L"rcsetup155.exe", 1 },

    { L"PathsParser",             L"https://github.com/spokwn/PathsParser/releases/download/v1.1/PathsParser.exe", L"PathsParser.exe", 2 },
    { L"Detect It Easy",          L"https://github.com/horsicq/Detect-It-Easy/releases/download/Beta/die_win64_portable_3.10_x64.zip", L"die_win64_portable_3.10_x64.zip", 2 },
    { L"Recaf CLI",               L"https://github.com/Col-E/Recaf-Launcher/releases/download/0.8.8/recaf-cli-0.8.8.jar", L"recaf-cli-0.8.8.jar", 2 },

    { L"BrowsingHistoryView",     L"https://www.nirsoft.net/utils/browsinghistoryview.zip", L"browsinghistoryview.zip", 3 },
    { L"AlternateStreamView",     L"https://www.nirsoft.net/utils/alternatestreamview-x64.zip", L"alternatestreamview-x64.zip", 3 },
    { L"WinDefLogView",           L"https://www.nirsoft.net/utils/windeflogview.zip", L"windeflogview.zip", 3 },
    { L"VolatilityWorkbench",     L"https://www.osforensics.com/downloads/VolatilityWorkbench.zip", L"VolatilityWorkbench.zip", 3 },
    { L"KernelLiveDumpTool",      L"https://github.com/spokwn/KernelLiveDumpTool/releases/download/v1.1/KernelLiveDumpTool.exe", L"KernelLiveDumpTool.exe", 3 },
    { L"FTK Imager",              L"https://github.com/HolyWorldWEB/holy-checker/releases/download/v1.0.1/FTK.Imager.8.3.0.27.zip", L"FTK.Imager.8.3.0.27.zip", 3 }
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
HFONT g_tinyFont = nullptr;
ULONG_PTR g_gdiplusToken = 0;

std::wstring g_appDir;
std::wstring g_downloadDir;
std::wstring g_extractDir;
int g_currentTab = 0;
std::atomic<int> g_progressPercent{0};
std::atomic<bool> g_deleteAllBusy{false};
std::mutex g_busyMutex;
std::set<int> g_busyItems;
std::mutex g_logMutex;
std::vector<std::wstring> g_logLines;
std::vector<Particle> g_particles;
std::vector<Star> g_staticStars;
std::vector<Comet> g_comets;
std::mutex g_processMutex;
std::vector<LaunchedProcess> g_launchedProcesses;
ULONGLONG g_lastCometSpawn = 0;
bool g_particlesPaused = false;

bool BasicPayloadCheck(const std::wstring& path, const std::wstring& fileName);
void LayoutControls(HWND hwnd);
void RefreshItemButtons(int itemIndex);

static void AddLog(const std::wstring& text) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logLines.push_back(text);
    if (g_logLines.size() > 100) g_logLines.erase(g_logLines.begin(), g_logLines.begin() + (g_logLines.size() - 100));
    if (g_mainWindow) InvalidateRect(g_mainWindow, nullptr, FALSE);
}
