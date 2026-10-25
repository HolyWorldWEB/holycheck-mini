int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    HandleSet instanceLocks;
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 1;
    instanceLocks.Add(token);
    DWORD tokenBytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &tokenBytes);
    if (!tokenBytes || tokenBytes > 65536) return 1;
    std::vector<BYTE> tokenData(tokenBytes);
    if (!GetTokenInformation(token, TokenUser, tokenData.data(), tokenBytes, &tokenBytes)) return 1;
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(tokenData.data())->User.Sid, &sid)) return 1;
    const std::wstring mutexName = L"Global\\HolyCheck-" + std::wstring(sid);
    LocalFree(sid);
    HANDLE singleton = CreateMutexW(nullptr, FALSE, mutexName.c_str());
    const DWORD mutexError = GetLastError();
    if (!instanceLocks.Add(singleton)) return 1;
    if (mutexError == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"HolyCheck уже запущен для этого пользователя.", L"HolyCheck", MB_OK);
        return 0;
    }
    FullLogSession journal;
    const DWORD logError = journal.Start();
    if (logError != ERROR_SUCCESS) {
        const auto message = L"Не удалось открыть Загрузки\\holycheckfull.txt (код " + std::to_wstring(logError) +
            L"). Полный журнал недоступен; проверьте права и отсутствие ссылок/занятости файла.";
        MessageBoxW(nullptr,message.c_str(),L"HolyCheck",MB_OK|MB_ICONWARNING);
    }
    g_instance = instance;
    srand(static_cast<unsigned int>(time(nullptr)));

    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    FullLog(L"STARTUP COM=" + std::to_wstring(com));

    GdiplusStartupInput gdiplusInput;
    if (GdiplusStartup(&g_gdiplusToken, &gdiplusInput, nullptr) != Ok) {
        MessageBoxW(nullptr, L"Не удалось запустить GDI+.", L"HolyCheck", MB_OK | MB_ICONERROR);
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }

    INITCOMMONCONTROLSEX commonControls{};
    commonControls.dwSize = sizeof(commonControls);
    commonControls.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&commonControls);

    if (!InitDownloadDirectory()) {
        FullLog(L"STARTUP storage failed code=" + std::to_wstring(GetLastError()));
        MessageBoxW(nullptr, L"Не удалось создать папку HolyCheck в Загрузках. Проверьте доступ и отсутствие junction/reparse в пути.", L"HolyCheck", MB_OK | MB_ICONERROR);
        GdiplusShutdown(g_gdiplusToken);
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }

    FullLog(L"STARTUP storage ready; five tab folders");
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = static_cast<HICON>(LoadImageW(instance,MAKEINTRESOURCEW(IDI_HOLYCHECK),IMAGE_ICON,
        GetSystemMetrics(SM_CXICON),GetSystemMetrics(SM_CYICON),LR_SHARED));
    wc.hIconSm = static_cast<HICON>(LoadImageW(instance,MAKEINTRESOURCEW(IDI_HOLYCHECK),IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),GetSystemMetrics(SM_CYSMICON),LR_SHARED));
    if(!wc.hIcon||!wc.hIconSm)FullLog(L"ICON resource missing; build and link parts/app_icon.rc");
    if(!wc.hIcon)wc.hIcon=LoadIconW(nullptr,IDI_APPLICATION);
    if(!wc.hIconSm)wc.hIconSm=wc.hIcon;
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kWindowClass;

    if (!RegisterClassExW(&wc)) {
        FullLog(L"STARTUP RegisterClass error="+std::to_wstring(GetLastError()));
        MessageBoxW(nullptr, L"Не удалось зарегистрировать окно.", L"HolyCheck", MB_OK | MB_ICONERROR);
        GdiplusShutdown(g_gdiplusToken);
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }

    g_mainWindow = CreateWindowExW(
        0, kWindowClass, kWindowTitle,
        WS_OVERLAPPEDWINDOW | WS_CLIPSIBLINGS,
        CW_USEDEFAULT, CW_USEDEFAULT, 1120, 760,
        nullptr, nullptr, instance, nullptr);

    if (!g_mainWindow) {
        FullLog(L"STARTUP CreateWindow error="+std::to_wstring(GetLastError()));
        MessageBoxW(nullptr, L"Не удалось создать окно.", L"HolyCheck", MB_OK | MB_ICONERROR);
        GdiplusShutdown(g_gdiplusToken);
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }

    // Тёмная рамка окна на Windows 10/11. Номера атрибута отличаются между
    // старыми и новыми сборками Windows, поэтому пробуем документированные/legacy
    // варианты без зависимости от конкретной версии SDK.
    BOOL dark = TRUE;
    const DWORD darkModeAttributes[] = { 19u, 20u };
    for (DWORD attribute : darkModeAttributes) {
        if (SUCCEEDED(DwmSetWindowAttribute(g_mainWindow, attribute, &dark, sizeof(dark))))
            break;
    }

    ShowWindow(g_mainWindow, showCommand);
    UpdateWindow(g_mainWindow);

    MSG msg{}; BOOL messageStatus=0;
    while ((messageStatus=GetMessageW(&msg, nullptr, 0, 0)) > 0) {
        // Only Tab is routed as dialog navigation. Do not turn Return/Escape
        // into unrelated default-button commands or change native Space clicks.
        if(msg.message==WM_KEYDOWN&&msg.wParam==VK_TAB) {
            SetKeyboardNavigation(true);
            if(IsDialogMessageW(g_mainWindow,&msg))continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    FullLog(L"MESSAGE LOOP end status="+std::to_wstring(messageStatus));
    JoinWorkers();
    if (g_gdiplusToken) GdiplusShutdown(g_gdiplusToken);
    if (SUCCEEDED(com)) CoUninitialize();
    return static_cast<int>(msg.wParam);
}
