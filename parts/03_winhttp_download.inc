bool DownloadHttpsFile(int itemIndex, const std::wstring& url, const std::wstring& finalPath,
                       const std::wstring& expectedFileName, std::wstring& error) {
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &components)) {
        error = L"Некорректный URL: " + Win32ErrorText(GetLastError());
        return false;
    }
    if (components.nScheme != INTERNET_SCHEME_HTTPS) {
        error = L"Разрешены только HTTPS-ссылки.";
        return false;
    }

    std::wstring host(components.lpszHostName, components.dwHostNameLength);
    if (!IsApprovedDownloadHost(host)) {
        error = L"Домен загрузки не разрешён: " + host;
        return false;
    }

    std::wstring path;
    if (components.dwUrlPathLength) path.assign(components.lpszUrlPath, components.dwUrlPathLength);
    if (components.dwExtraInfoLength) path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    if (path.empty()) path = L"/";

    HINTERNET session = WinHttpOpen(
        L"HolyCheck/3.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!session) {
        error = L"WinHttpOpen: " + Win32ErrorText(GetLastError());
        return false;
    }

    WinHttpSetTimeouts(session, 30000, 30000, 30000, 30000);

    HINTERNET connect = WinHttpConnect(session, host.c_str(), components.nPort, 0);
    if (!connect) {
        error = L"WinHttpConnect: " + Win32ErrorText(GetLastError());
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect, L"GET", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request) {
        error = L"WinHttpOpenRequest: " + Win32ErrorText(GetLastError());
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy, sizeof(redirectPolicy));

    const std::wstring partPath = finalPath + L".part";
    DeleteFileW(partPath.c_str());
    bool ok = false;

    do {
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            error = L"WinHttpSendRequest: " + Win32ErrorText(GetLastError());
            break;
        }
        if (!WinHttpReceiveResponse(request, nullptr)) {
            error = L"WinHttpReceiveResponse: " + Win32ErrorText(GetLastError());
            break;
        }

        DWORD status = 0;
        DWORD statusSize = sizeof(status);
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                                 WINHTTP_NO_HEADER_INDEX)) {
            error = L"Не удалось получить HTTP-статус.";
            break;
        }
        if (status < 200 || status >= 300) {
            error = L"HTTP " + std::to_wstring(status);
            break;
        }

        DWORD finalUrlBytes = 0;
        WinHttpQueryOption(request, WINHTTP_OPTION_URL, nullptr, &finalUrlBytes);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && finalUrlBytes >= sizeof(wchar_t)) {
            std::vector<wchar_t> finalUrl(finalUrlBytes / sizeof(wchar_t) + 2, L'\0');
            if (WinHttpQueryOption(request, WINHTTP_OPTION_URL, finalUrl.data(), &finalUrlBytes)) {
                URL_COMPONENTS finalComponents{};
                finalComponents.dwStructSize = sizeof(finalComponents);
                finalComponents.dwSchemeLength = static_cast<DWORD>(-1);
                finalComponents.dwHostNameLength = static_cast<DWORD>(-1);
                if (!WinHttpCrackUrl(finalUrl.data(), 0, 0, &finalComponents) ||
                    finalComponents.nScheme != INTERNET_SCHEME_HTTPS) {
                    error = L"Небезопасное перенаправление заблокировано.";
                    break;
                }
                std::wstring finalHost(finalComponents.lpszHostName, finalComponents.dwHostNameLength);
                if (!IsApprovedDownloadHost(finalHost)) {
                    error = L"Перенаправление на неразрешённый домен: " + finalHost;
                    break;
                }
            }
        }

        DWORD totalBytes = 0;
        DWORD totalBytesSize = sizeof(totalBytes);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &totalBytes, &totalBytesSize,
                            WINHTTP_NO_HEADER_INDEX);

        HANDLE file = CreateFileW(partPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            error = L"Не удалось создать файл: " + Win32ErrorText(GetLastError());
            break;
        }

        bool streamOk = true;
        DWORD receivedTotal = 0;
        int lastPercent = -1;
        std::vector<unsigned char> buffer(64 * 1024);

        for (;;) {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available)) {
                error = L"WinHttpQueryDataAvailable: " + Win32ErrorText(GetLastError());
                streamOk = false;
                break;
            }
            if (available == 0) break;

            while (available > 0) {
                DWORD chunk = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
                DWORD read = 0;
                if (!WinHttpReadData(request, buffer.data(), chunk, &read)) {
                    error = L"WinHttpReadData: " + Win32ErrorText(GetLastError());
                    streamOk = false;
                    break;
                }
                if (read == 0) {
                    available = 0;
                    break;
                }

                DWORD written = 0;
                if (!WriteFile(file, buffer.data(), read, &written, nullptr) || written != read) {
                    error = L"Ошибка записи файла: " + Win32ErrorText(GetLastError());
                    streamOk = false;
                    break;
                }

                receivedTotal += read;
                available -= read;

                if (totalBytes > 0) {
                    int percent = static_cast<int>((static_cast<unsigned long long>(receivedTotal) * 100ULL) / totalBytes);
                    if (percent > 100) percent = 100;
                    if (percent != lastPercent) {
                        lastPercent = percent;
                        PostMessageW(g_mainWindow, WM_APP_DOWNLOAD_PROGRESS,
                                     static_cast<WPARAM>(itemIndex), static_cast<LPARAM>(percent));
                    }
                }
            }
            if (!streamOk) break;
        }

        if (streamOk) FlushFileBuffers(file);
        CloseHandle(file);
        if (!streamOk) break;

        if (!BasicPayloadCheck(partPath, expectedFileName)) {
            error = L"Сервер вернул файл неожиданного формата.";
            break;
        }

        if (!MoveFileExW(partPath.c_str(), finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            error = L"Не удалось сохранить файл: " + Win32ErrorText(GetLastError());
            break;
        }

        PostMessageW(g_mainWindow, WM_APP_DOWNLOAD_PROGRESS,
                     static_cast<WPARAM>(itemIndex), static_cast<LPARAM>(100));
        ok = true;
    } while (false);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    if (!ok) DeleteFileW(partPath.c_str());
    return ok;
}
