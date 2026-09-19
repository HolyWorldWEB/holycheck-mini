#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shldisp.h>
#include <winhttp.h>
#include <gdiplus.h>
#include <objidl.h>
#include <dwmapi.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <deque>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cwchar>
#include <cstring>
#include <initializer_list>
#include <ctime>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "advapi32.lib")

using namespace Gdiplus;

namespace {

#include "parts/01_prelude_globals.inc"
#include "parts/02_state_paths_urls.inc"
#include "parts/10_filecheck_clipboard.inc"
#include "parts/03_winhttp_download.inc"
#include "parts/04_zip_process_utils.inc"
#include "parts/06_download_methods_validation.inc"
#include "parts/07_download_workers_cleanup.inc"
#include "parts/08_ui_rendering_layout.inc"

} // namespace

#include "parts/09_window_main.inc"
