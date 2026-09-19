int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    g_instance = instance;

    HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

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
        MessageBoxW(nullptr, L"Не удалось создать папку загрузок в LocalAppData.", L"HolyCheck", MB_OK | MB_ICONERROR);
        GdiplusShutdown(g_gdiplusToken);
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = nullptr;
    wc.lpszClassName = kWindowClass;

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Не удалось зарегистрировать окно.", L"HolyCheck", MB_OK | MB_ICONERROR);
        GdiplusShutdown(g_gdiplusToken);
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }

    g_mainWindow = CreateWindowExW(
        0, kWindowClass, kWindowTitle,
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        CW_USEDEFAULT, CW_USEDEFAULT, 1120, 760,
        nullptr, nullptr, instance, nullptr);

    if (!g_mainWindow) {
        MessageBoxW(nullptr, L"Не удалось создать окно.", L"HolyCheck", MB_OK | MB_ICONERROR);
        GdiplusShutdown(g_gdiplusToken);
        if (SUCCEEDED(com)) CoUninitialize();
        return 1;
    }

    // Тёмная рамка окна на Windows 10/11. Это только визуальный атрибут DWM.
    BOOL dark = TRUE;
    const DWORD kDarkModeAttribute = 20;
    DwmSetWindowAttribute(g_mainWindow, kDarkModeAttribute, &dark, sizeof(dark));

    ShowWindow(g_mainWindow, showCommand);
    UpdateWindow(g_mainWindow);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_gdiplusToken) GdiplusShutdown(g_gdiplusToken);
    if (SUCCEEDED(com)) CoUninitialize();
    return static_cast<int>(msg.wParam);
}
