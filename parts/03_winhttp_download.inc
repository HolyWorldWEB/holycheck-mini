// One synchronous session per existing worker; never create extra threads or
// share request handles. Thread-local destruction closes it when the pool exits.
struct WorkerHttpSession {
    HINTERNET handle=nullptr;
    ~WorkerHttpSession(){if(handle)WinHttpCloseHandle(handle);}
    HINTERNET Get(std::wstring& error) {
        if(handle)return handle;
        handle=WinHttpOpen(L"HolyCheck/3.0",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
        if(!handle){error=L"WinHttpOpen: "+Win32ErrorText(GetLastError());return nullptr;}
        if(!WinHttpSetTimeouts(handle,10000,15000,15000,30000)) {
            const auto code=GetLastError();WinHttpCloseHandle(handle);handle=nullptr;
            error=L"Не удалось настроить таймауты: "+Win32ErrorText(code);return nullptr;
        }
        (void)0;return handle;
    }
};
static thread_local WorkerHttpSession g_workerHttpSession;
struct InternetScope {
    HINTERNET& connect;HINTERNET& request;
    ~InternetScope(){if(request)WinHttpCloseHandle(request);if(connect)WinHttpCloseHandle(connect);}
};
static bool RetryableTransportError(DWORD code) {
    return code==ERROR_WINHTTP_TIMEOUT||code==ERROR_WINHTTP_CANNOT_CONNECT||
        code==ERROR_WINHTTP_CONNECTION_ERROR||code==ERROR_WINHTTP_RESEND_REQUEST||code==ERROR_WINHTTP_NAME_NOT_RESOLVED;
}
static bool ParseRetryAfter(const std::wstring& value,unsigned& delayMs) {
    const auto parsed=HolyNet::RetrySeconds(value,delayMs);
    if(parsed==HolyNet::SecondsResult::Ready)return true;
    if(parsed==HolyNet::SecondsResult::TooLong)return false; // Never retry earlier than a long server delay.
    SYSTEMTIME date{};FILETIME target{},now{};
    if(!value.empty()&&WinHttpTimeToSystemTime(value.c_str(),&date)&&SystemTimeToFileTime(&date,&target)) {
        GetSystemTimeAsFileTime(&now);ULARGE_INTEGER a{},b{};
        a.HighPart=target.dwHighDateTime;a.LowPart=target.dwLowDateTime;
        b.HighPart=now.dwHighDateTime;b.LowPart=now.dwLowDateTime;
        const auto milliseconds=a.QuadPart>b.QuadPart?(a.QuadPart-b.QuadPart+9999)/10000:0;
        if(milliseconds>HolyNet::kMaxRetryWaitMs)return false;
        delayMs=static_cast<unsigned>(milliseconds);return true;
    }
    delayMs=0;return true; // Absent/invalid header uses the bounded backoff.
}
static bool ReadRetryAfter(HINTERNET request,unsigned& delayMs) {
    wchar_t text[256]{};DWORD bytes=sizeof(text);
    if(!WinHttpQueryHeaders(request,WINHTTP_QUERY_RETRY_AFTER,WINHTTP_HEADER_NAME_BY_INDEX,
        text,&bytes,WINHTTP_NO_HEADER_INDEX)) {
        if(GetLastError()==ERROR_WINHTTP_HEADER_NOT_FOUND){delayMs=0;return true;}
        return false; // Cannot safely honour an unreadable/oversized delay.
    }
    if(bytes>=sizeof(text)||bytes%sizeof(wchar_t))return false;
    const auto length=bytes/sizeof(wchar_t);text[length]=0;
    std::wstring value(text);
    if(value.size()!=length&&value.size()+1!=length)return false;
    while(!value.empty()&&(value.front()==L' '||value.front()==L'\t'))value.erase(value.begin());
    while(!value.empty()&&(value.back()==L' '||value.back()==L'\t'))value.pop_back();
    return ParseRetryAfter(value,delayMs);
}
struct PartialDownloadScope {
    const std::wstring& path;
    bool& owned;
    bool& committed;
    CreatedFileIdentity identity;
    HolyNet::RetryState& retry;
    ~PartialDownloadScope() noexcept {
        try {
            if(owned&&!committed&&(!IsOwnHolyCheckDirectory(g_appDir)||!identity.Remove(g_appDir))) {
                retry.retryable=false;(void)0;
            }
        }catch(...){retry.retryable=false;(void)0;}
    }
};

static bool ParseApprovedUrl(const std::wstring& url, URL_COMPONENTS& c,
                             std::wstring& host, std::wstring& path) {
    std::wstring checkedHost;
    if (!HolyUrl::ParseAuthority(url, checkedHost)) return false;
    c = {}; c.dwStructSize = sizeof(c);
    c.dwSchemeLength = c.dwHostNameLength = c.dwUrlPathLength = c.dwExtraInfoLength =
        c.dwUserNameLength = c.dwPasswordLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &c) ||
        c.nScheme != INTERNET_SCHEME_HTTPS || c.nPort != INTERNET_DEFAULT_HTTPS_PORT ||
        !c.dwHostNameLength || c.dwUserNameLength || c.dwPasswordLength) return false;
    const size_t authorityEnd = url.find_first_of(L"/?#", 8);
    if (url.substr(8, authorityEnd == std::wstring::npos ? authorityEnd : authorityEnd - 8).find(L'@') != std::wstring::npos)
        return false;
    host.assign(c.lpszHostName, c.dwHostNameLength);
    if (!IsApprovedDownloadHost(host) || LowerAscii(host) != checkedHost) return false;
    path.clear();
    if (c.dwUrlPathLength) path.assign(c.lpszUrlPath, c.dwUrlPathLength);
    if (path.empty()) path = L"/";
    if (c.dwExtraInfoLength) path.append(c.lpszExtraInfo, c.dwExtraInfoLength);
    return true;
}

static bool QueryVerifiedRequestUrl(HINTERNET request, std::wstring& url) {
    if (!HolyUrl::ReadOptionUrl([&](wchar_t* buffer, size_t& bytes) {
        DWORD count = static_cast<DWORD>(bytes);
        const BOOL ok = WinHttpQueryOption(request, WINHTTP_OPTION_URL, buffer, &count);
        bytes = count;
        if (ok) return HolyUrl::QueryResult::Success;
        return GetLastError() == ERROR_INSUFFICIENT_BUFFER
            ? HolyUrl::QueryResult::InsufficientBuffer : HolyUrl::QueryResult::Failure;
    }, url)) return false;
    URL_COMPONENTS c{}; std::wstring host, path;
    return ParseApprovedUrl(url, c, host, path);
}

// Metadata only: bounded in-memory download, never written to disk or executed.
// Uses the existing worker; no UI-thread I/O, shell, HTML parsing or new threads.
static bool FetchSignedUpdateManifest(std::vector<BYTE>& bytes, std::wstring& error) {
    bytes.clear();
    const ULONGLONG started = GetTickCount64();
    const auto cancelled = [&] { return g_cancelRequested.load() || GetTickCount64() - started >= 30000; };
    HINTERNET session = WinHttpOpen(L"HolyCheck/3.0 Updates", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { error = L"Не удалось открыть соединение с сервером подписанного каталога."; return false; }
    struct SessionScope { HINTERNET h; ~SessionScope() { WinHttpCloseHandle(h); } } scope{session};
    HINTERNET connect = nullptr, request = nullptr;
    InternetScope handles{connect, request};
    if (!WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000)) {
        error = L"Не удалось установить таймауты каталога обновлений."; return false;
    }
    std::wstring current = HolyUpdateConfig::kManifestUrl;
    for (unsigned hop = 0; hop <= 5; ++hop) {
        if (cancelled()) { error = L"Получение каталога отменено или превышено время ожидания."; return false; }
        URL_COMPONENTS c{}; std::wstring host, path;
        if (!ParseApprovedUrl(current, c, host, path)) {
            error = L"Недопустимый HTTPS-адрес каталога обновлений или его перенаправления."; return false;
        }
        if (request) { WinHttpCloseHandle(request); request = nullptr; }
        if (connect) { WinHttpCloseHandle(connect); connect = nullptr; }
        connect = WinHttpConnect(session, host.c_str(), c.nPort, 0);
        if (connect) request = WinHttpOpenRequest(connect, L"GET", path.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        DWORD auth = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        DWORD disable = WINHTTP_DISABLE_COOKIES;
        if (!request || !WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)) ||
            !WinHttpSetOption(request, WINHTTP_OPTION_AUTOLOGON_POLICY, &auth, sizeof(auth)) ||
            !WinHttpSetOption(request, WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable)) ||
            !WinHttpSendRequest(request, L"Cache-Control: no-cache\r\n", static_cast<DWORD>(-1),
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request, nullptr)) {
            (void)0;
            error = L"Не удалось получить подписанный каталог обновлений. Загрузка не разрешена."; return false;
        }
        std::wstring effective;
        if (!QueryVerifiedRequestUrl(request, effective)) {
            error = L"Не удалось проверить конечный URL каталога обновлений."; return false;
        }
        DWORD status = 0, size = sizeof(status);
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
            error = L"Недоступен HTTP-статус каталога обновлений."; return false;
        }
        (void)0;
        if (status == 200) {
            unsigned char chunk[16384];
            const bool ok = HolyManifest::ReadBounded([&](unsigned char* out, size_t capacity, size_t& got) {
                if (cancelled()) return false;
                DWORD n = 0;
                const BOOL read = WinHttpReadData(request, out, static_cast<DWORD>(capacity), &n);
                got = n; return read != FALSE && !cancelled();
            }, chunk, sizeof(chunk), bytes);
            if (!ok) error = L"Каталог обновлений пуст, превышает 1 МБ, недоступен либо получение отменено.";
            return ok;
        }
        if (hop == 5 || (status != 301 && status != 302 && status != 303 && status != 307 && status != 308)) {
            error = L"Сервер каталога обновлений вернул HTTP " + std::to_wstring(status) + L" или слишком много перенаправлений.";
            return false;
        }
        size = 0;
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
            nullptr, &size, WINHTTP_NO_HEADER_INDEX) || GetLastError() != ERROR_INSUFFICIENT_BUFFER ||
            size < sizeof(wchar_t) || size > 65536 || size % sizeof(wchar_t)) {
            error = L"Некорректное перенаправление каталога обновлений."; return false;
        }
        std::vector<wchar_t> location(size / sizeof(wchar_t) + 1, 0);
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
            location.data(), &size, WINHTTP_NO_HEADER_INDEX)) {
            error = L"Не удалось прочитать перенаправление каталога обновлений."; return false;
        }
        wchar_t combined[32769]{}; DWORD count = ARRAYSIZE(combined);
        if (FAILED(UrlCombineW(effective.c_str(), location.data(), combined, &count, URL_DONT_SIMPLIFY))) {
            error = L"Некорректный URL перенаправления каталога обновлений."; return false;
        }
        current = combined; // Checked before opening the next request.
    }
    return false;
}

static bool PublishOpenDownload(HANDLE file,const std::wstring& destination) {
    if(!HolyFiles::LocalPath(destination)||destination.size()>32760){SetLastError(ERROR_INVALID_NAME);return false;}
    const size_t nameBytes=destination.size()*sizeof(wchar_t);
    std::vector<BYTE> bytes(offsetof(FILE_RENAME_INFO,FileName)+nameBytes+sizeof(wchar_t),0);
    auto* info=reinterpret_cast<FILE_RENAME_INFO*>(bytes.data());
    info->ReplaceIfExists=FALSE;info->RootDirectory=nullptr;info->FileNameLength=static_cast<DWORD>(nameBytes);
    memcpy(info->FileName,destination.data(),nameBytes);
    return SetFileInformationByHandle(file,FileRenameInfo,info,static_cast<DWORD>(bytes.size()))!=FALSE;
}

static bool DownloadHttpsFileAttempt(int itemIndex,const std::wstring& url,const std::wstring& finalPath,
                       const std::wstring& expectedFileName,std::wstring& error,
                       ULONGLONG deadline,HolyNet::RetryState& retry) {
    [[maybe_unused]] const auto attemptStart=GetTickCount64();
    auto cancelled = [&] { return g_cancelRequested.load() || GetTickCount64() >= deadline; };
    constexpr unsigned long long kMaxDownloadBytes = 2ULL * 1024ULL * 1024ULL * 1024ULL;
    if (!HasPinnedSha256(itemIndex) || finalPath != ItemPath(itemIndex) ||
        !IsSimpleFileName(expectedFileName)) { error = L"Недоверенная загрузка."; return false; }
    HandleSet directoryLocks;
    if (!LockDirectoryChain(ItemDirectory(itemIndex), directoryLocks)) {
        error = L"Небезопасная папка загрузки."; return false;
    }
    [[maybe_unused]] const auto sessionStart=GetTickCount64();
    HINTERNET session=g_workerHttpSession.Get(error);
    if(!session)return false;
    (void)0;
    HINTERNET connect=nullptr,request=nullptr;
    InternetScope internet{connect,request};
    bool ready = false, ok = false, ownsPart = false;
    std::wstring current = url;
    for (unsigned hop = 0; hop <= 10; ++hop) {
        if (cancelled()) { error = L"Загрузка отменена или превышено время операции."; break; }
        URL_COMPONENTS c{}; std::wstring host, path;
        if (!ParseApprovedUrl(current, c, host, path)) { error = L"Небезопасный URL заблокирован."; break; }
        (void)0;
        if (request) { WinHttpCloseHandle(request); request = nullptr; }
        if (connect) { WinHttpCloseHandle(connect); connect = nullptr; }
        connect = WinHttpConnect(session, host.c_str(), c.nPort, 0);
        if(!connect){const auto code=GetLastError();retry.retryable=RetryableTransportError(code);error=L"WinHttpConnect: "+Win32ErrorText(code);break;}
        request = WinHttpOpenRequest(connect, L"GET", path.c_str(), nullptr,
                                    WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!request) { error = L"WinHttpOpenRequest: " + Win32ErrorText(GetLastError()); break; }
        DWORD policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        DWORD auth = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        if (!WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY, &policy, sizeof(policy)) ||
            !WinHttpSetOption(request, WINHTTP_OPTION_AUTOLOGON_POLICY, &auth, sizeof(auth))) {
            error = L"Не удалось включить безопасную политику WinHTTP."; break;
        }
        [[maybe_unused]] const auto headersStart=GetTickCount64();
        if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request, nullptr)) {
            const auto code=GetLastError();retry.retryable=RetryableTransportError(code);
            (void)0;
            error=L"WinHTTP: "+Win32ErrorText(code);break;
        }
        (void)0;
        std::wstring effective;
        if (!QueryVerifiedRequestUrl(request, effective)) {
            error = L"Не удалось проверить итоговый URL. Загрузка заблокирована."; break;
        }
        DWORD status = 0, bytes = sizeof(status);
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                 WINHTTP_HEADER_NAME_BY_INDEX, &status, &bytes, WINHTTP_NO_HEADER_INDEX)) {
            error = L"Не удалось получить HTTP-статус."; break;
        }
        (void)0;
        if (status == 200) { ready = true; break; }
        if (hop == 10 || (status != 301 && status != 302 && status != 303 && status != 307 && status != 308)) {
            retry.retryable=HolyNet::RetryStatus(status)&&ReadRetryAfter(request,retry.delayMs);
            error=L"HTTP "+std::to_wstring(status)+L" или превышен лимит перенаправлений.";
            if(HolyNet::RetryStatus(status)&&!retry.retryable)error+=L" Сервер запретил быстрый повтор либо Retry-After недоступен; повторите позже.";
            break;
        }
        bytes = 0;
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                nullptr, &bytes, WINHTTP_NO_HEADER_INDEX) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < 2 || bytes > 65536 || bytes % 2) {
            error = L"Некорректный Location."; break;
        }
        std::vector<wchar_t> location(bytes / sizeof(wchar_t) + 1, L'\0');
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                 location.data(), &bytes, WINHTTP_NO_HEADER_INDEX)) {
            error = L"Не удалось прочитать Location."; break;
        }
        wchar_t combined[32769]{}; DWORD length = ARRAYSIZE(combined);
        if (FAILED(UrlCombineW(effective.c_str(), location.data(), combined, &length, URL_DONT_SIMPLIFY))) {
            error = L"Некорректный URL перенаправления."; break;
        }
        current = combined; // validated at top of loop, BEFORE any new request
    }
    // A GUID name and CREATE_NEW avoid reuse or truncation of an attacker's .part.
    GUID id{}; wchar_t guid[40]{};
    if (FAILED(CoCreateGuid(&id)) || !StringFromGUID2(id, guid, ARRAYSIZE(guid))) {
        ready = false; error = L"Не удалось создать безопасное имя временного файла.";
    }
    const std::wstring partPath = finalPath + L"." + guid + L".part";
    PartialDownloadScope partial{partPath, ownsPart, ok, {}, retry};
    do {
        if (!ready) break;
        DWORD totalBytes = 0;
        DWORD totalBytesSize = sizeof(totalBytes);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &totalBytes, &totalBytesSize,
                            WINHTTP_NO_HEADER_INDEX);
        if (totalBytes > 0 && static_cast<unsigned long long>(totalBytes) > kMaxDownloadBytes) {
            error = L"Файл превышает допустимый размер загрузки (2 ГБ).";
            break;
        }

        HANDLE file = CreateFileW(partPath.c_str(), GENERIC_READ|GENERIC_WRITE|DELETE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            error = L"Не удалось создать файл: " + Win32ErrorText(GetLastError());
            break;
        }

        HandleSet outputHandles;
        outputHandles.Add(file);
        ownsPart = true;
        if(!partial.identity.Capture(partPath,file)){error=L"Не удалось подтвердить идентификатор временного файла.";break;}
        bool streamOk = true;
        unsigned long long receivedTotal = 0;
        int lastPercent = -1;
        std::vector<unsigned char> buffer(64 * 1024);

        [[maybe_unused]] const auto readStart=GetTickCount64();
        for (;;) {
            if(cancelled()){streamOk=false;error=L"Загрузка отменена или превышено время операции.";break;}
            DWORD read=0;
            // ReceiveResponse completed above; fixed 64 KiB synchronous reads
            // avoid QueryDataAvailable's extra copy/call. TRUE + zero is EOF.
            if(!WinHttpReadData(request,buffer.data(),static_cast<DWORD>(buffer.size()),&read)) {
                const auto code=GetLastError();retry.retryable=RetryableTransportError(code);
                error=L"WinHttpReadData: "+Win32ErrorText(code);streamOk=false;break;
            }
            if(!read)break;
            if(read>kMaxDownloadBytes-receivedTotal) {
                error=L"Файл превысил допустимый размер загрузки (2 ГБ).";streamOk=false;break;
            }
            DWORD written=0;
            if(!WriteFile(file,buffer.data(),read,&written,nullptr)||written!=read) {
                error=L"Ошибка записи файла: "+Win32ErrorText(GetLastError());streamOk=false;break;
            }
            receivedTotal+=read;
            if(totalBytes) {
                const int percent=static_cast<int>(std::min(100ULL,receivedTotal*100ULL/totalBytes));
                if(percent!=lastPercent){lastPercent=percent;PostMessageW(g_mainWindow,WM_APP_DOWNLOAD_PROGRESS,
                    static_cast<WPARAM>(itemIndex),static_cast<LPARAM>(percent));}
            }
        }
        (void)0;

        if (streamOk && !FlushFileBuffers(file)) {
            streamOk = false;
            error = L"Не удалось сбросить данные файла на диск.";
        }
        // Retain the original exclusive CREATE_NEW handle through verification
        // and rename. No check-to-path-replacement gap and no extra rehash.
        if (!streamOk) break;
        (void)0;
        if(totalBytes&&receivedTotal!=totalBytes) {
            retry.retryable=receivedTotal<totalBytes;error=L"Неполное тело HTTP-ответа.";break;
        }
        if (cancelled()) { error = L"Загрузка отменена."; break; }

        if(!BasicPayloadCheck(partPath,expectedFileName,file)) {
            error=L"Сервер вернул файл неожиданного формата.";break;
        }

        [[maybe_unused]] const auto verifyStart=GetTickCount64();
        const bool verified=VerifyPinnedPayloadForItem(itemIndex,partPath,error,file);
        (void)0;
        if(!verified)break; // Never retry/accept a new hash to mask trust failure.

        [[maybe_unused]] const auto publishWait=GetTickCount64();
        std::unique_lock<std::recursive_mutex> publishGuard(g_tabFileMutex[kItems[itemIndex].tab]);
        (void)0;
        if(cancelled()){error=L"Операция отменена до сохранения файла.";break;}
        if (!PublishOpenDownload(file,finalPath)) {
            error = L"Не удалось сохранить файл: " + Win32ErrorText(GetLastError());
            break;
        }

        PostMessageW(g_mainWindow, WM_APP_DOWNLOAD_PROGRESS,
                     static_cast<WPARAM>(itemIndex), static_cast<LPARAM>(100));
        ok = true;
    } while (false);

    (void)0;
    (void)0;
    return ok;
}

// Three total attempts, one shared wall-clock budget, cancellable backoff.
// A failed attempt's GUID .part is rolled back BEFORE this schedules another.
bool DownloadHttpsFile(int itemIndex,const std::wstring& url,const std::wstring& finalPath,
                       const std::wstring& expectedFileName,std::wstring& error) {
    // A website action is not permission to download its contents as a payload.
    if(itemIndex<0||static_cast<size_t>(itemIndex)>=kItemCount||kItems[itemIndex].website) {
        error=L"Эта кнопка открывает страницу в браузере и не скачивает файл через HolyCheck.";return false;
    }
    // Before creating a session, opening a URL or touching a destination file.
    if(RejectReportedPayload(itemIndex,error))return false;

    if(!g_cancelRequested.load())PostMessageW(g_mainWindow,WM_APP_DOWNLOAD_STARTED,static_cast<WPARAM>(itemIndex),0);
    const auto started=GetTickCount64(),deadline=started+15ULL*60*1000;
    const auto stopped=[] {return g_cancelRequested.load();};
    const bool ok=HolyNet::Run([&](unsigned attempt,HolyNet::RetryState& retry) {
        error.clear();
        (void)0;
        if(attempt)PostMessageW(g_mainWindow,WM_APP_DOWNLOAD_PROGRESS,static_cast<WPARAM>(itemIndex),0);
        const bool success=DownloadHttpsFileAttempt(itemIndex,url,finalPath,expectedFileName,error,deadline,retry);
        (void)0;
        return success;
    },[]{return GetTickCount64();},[&](unsigned delay) {
        (void)0;
        const auto until=GetTickCount64()+delay;
        for(;;) {
            const auto now=GetTickCount64();
            if(stopped()||now>=deadline)return false;
            if(now>=until)break;
            Sleep(static_cast<DWORD>(std::min<ULONGLONG>(until-now,100)));
        }
        return !stopped();
    },stopped,deadline);
    if(!ok) {
        if(stopped())error=L"Загрузка отменена.";
        else if(GetTickCount64()>=deadline)error=L"Превышено общее время загрузки (15 минут).";
    }
    (void)0;
    return ok;
}
