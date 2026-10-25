#include "05_safe_paths.inc"

struct CryptoScope {
    HCRYPTPROV& provider; HCRYPTHASH& hash;
    ~CryptoScope() {
        if (hash) CryptDestroyHash(hash);
        if (provider) CryptReleaseContext(provider, 0);
    }
};

static bool ReadHeader(const std::wstring& path,std::vector<unsigned char>& out,size_t bytes=16,HANDLE alreadyOpen=INVALID_HANDLE_VALUE) {
    HandleSet fileScope;HANDLE file=alreadyOpen;
    if(file==INVALID_HANDLE_VALUE) {
        file=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
        if(!fileScope.Add(file))return false;
    }
    LARGE_INTEGER zero{};if(!SetFilePointerEx(file,zero,nullptr,FILE_BEGIN))return false;
    if (bytes > MAXDWORD) return false;
    out.assign(bytes, 0);
    DWORD read = 0;
    BOOL ok = ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    if (!ok) return false;
    out.resize(read);
    return true;
}

static bool StartsWith(const std::vector<unsigned char>& b, std::initializer_list<unsigned char> sig) {
    if (b.size() < sig.size()) return false;
    return std::equal(sig.begin(), sig.end(), b.begin());
}

static std::wstring LowerFileName(std::wstring s) {
    for (wchar_t& ch : s) if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
    return s;
}

static bool IsValidPeExecutable(const std::wstring& path,std::wstring* diagnostic=nullptr,HANDLE alreadyOpen=INVALID_HANDLE_VALUE) {
    auto fail = [&](const std::wstring& text) { if (diagnostic) *diagnostic = text; return false; };
    HandleSet locks;
    HANDLE file=alreadyOpen;
    if(file==INVALID_HANDLE_VALUE) {
        if(!LockRegularFile(path,locks))
            return fail(L"Файл недоступен/занят либо путь небезопасен. Win32: "+Win32ErrorText(GetLastError()));
        file=locks.handles.back();
    }
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file, &length) || length.QuadPart < 0)
        return fail(L"Не удалось получить размер EXE.");
    DWORD readError = ERROR_SUCCESS;
    const auto result = HolyPe::Inspect([&](uint64_t offset, void* buffer, size_t bytes) {
        if (bytes > MAXDWORD || offset > static_cast<uint64_t>(INT64_MAX)) {
            readError = ERROR_INVALID_PARAMETER; return false;
        }
        LARGE_INTEGER position{}; position.QuadPart = static_cast<LONGLONG>(offset);
        DWORD count = 0;
        if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN) ||
            !ReadFile(file, buffer, static_cast<DWORD>(bytes), &count, nullptr)) {
            readError = GetLastError(); return false;
        }
        if (count != bytes) { readError = ERROR_HANDLE_EOF; return false; }
        return true;
    }, static_cast<uint64_t>(length.QuadPart));
    if (result.kind == HolyPe::Kind::Dll)
        return fail(L"Обнаружена DLL, а не самостоятельно запускаемый EXE.");
    if (result.kind != HolyPe::Kind::Exe) {
        std::wstring text = L"PE не прошёл проверку: " + std::wstring(HolyPe::ProblemText(result.problem)) + L".";
        if (readError != ERROR_SUCCESS) text += L" Win32: " + Win32ErrorText(readError);
        return fail(text);
    }
    if (diagnostic) diagnostic->clear();
    return true;
}

bool BasicPayloadCheck(const std::wstring& path,const std::wstring& fileName,HANDLE alreadyOpen) {
    std::vector<unsigned char> head;
    if (!ReadHeader(path, head,16,alreadyOpen)) return false;
    if (head.empty()) return false;

    const std::wstring lower = LowerFileName(fileName);
    auto ends = [&](const wchar_t* suffix) {
        const std::wstring s = suffix;
        return lower.size() >= s.size() && lower.compare(lower.size() - s.size(), s.size(), s) == 0;
    };

    if (ends(L".exe")) return IsValidPeExecutable(path,nullptr,alreadyOpen);
    if (ends(L".msi")) return StartsWith(head, {0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1});
    if (ends(L".zip") || ends(L".jar")) {
        return StartsWith(head, {0x50,0x4B,0x03,0x04}) || StartsWith(head, {0x50,0x4B,0x05,0x06}) || StartsWith(head, {0x50,0x4B,0x07,0x08});
    }
    if (ends(L".7z")) return StartsWith(head, {0x37,0x7A,0xBC,0xAF,0x27,0x1C});
    if (ends(L".rar")) return StartsWith(head, {0x52,0x61,0x72,0x21,0x1A,0x07});
    return true;
}

static bool GetOpenFileSha256Hex(HANDLE file,std::wstring& hex) {
    hex.clear();LARGE_INTEGER beginning{};
    if(!SetFilePointerEx(file,beginning,nullptr,FILE_BEGIN))return false;
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    CryptoScope crypto{provider, hash};
    bool ok = CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES,
                                   CRYPT_VERIFYCONTEXT) != FALSE;
    if (ok) ok = CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) != FALSE;

    std::vector<BYTE> buffer(256 * 1024);
    while (ok) {
        if (g_cancelRequested.load()) { ok = false; break; }
        DWORD read = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr)) {
            ok = false;
            break;
        }
        if (read == 0) break;
        if (!CryptHashData(hash, buffer.data(), read, 0)) {
            ok = false;
            break;
        }
    }

    BYTE digest[32]{};
    DWORD digestBytes = sizeof(digest);
    if (ok) ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &digestBytes, 0) != FALSE &&
                 digestBytes == sizeof(digest);

    if (ok) {
        static const wchar_t digits[] = L"0123456789abcdef";
        hex.reserve(64);
        for (BYTE b : digest) {
            hex.push_back(digits[(b >> 4) & 0x0F]);
            hex.push_back(digits[b & 0x0F]);
        }
    }

    return ok;
}

// In-memory proof reuse is limited to ONE operation on ONE worker. Every
// cached digest retains its no-write/no-delete-sharing handle and parent locks.
// No timestamp-only/sidecar/cross-click trust cache. Temporary downloads are
// excluded so their verified file can be renamed/rolled back normally.
struct HashReadProof { HandleSet locks; std::wstring digest; };
struct ScopedHashReads;
static thread_local ScopedHashReads* g_hashReads = nullptr;
struct ScopedHashReads {
    ScopedHashReads* previous = g_hashReads;
    std::map<std::wstring,std::unique_ptr<HashReadProof>> proofs;
    unsigned diskReads=0,hits=0; ULONGLONG hashMs=0,started=GetTickCount64();int item;
    explicit ScopedHashReads(int index):item(index){g_hashReads=this;}
    ScopedHashReads(const ScopedHashReads&)=delete;
    ScopedHashReads& operator=(const ScopedHashReads&)=delete;
    ~ScopedHashReads(){
        g_hashReads=previous;
        try { (void)0; } catch(...) {}
    }
};
static bool GetFileSha256Hex(const std::wstring& path,std::wstring& hex) {
    hex.clear();
    if(g_cancelRequested.load()){SetLastError(ERROR_CANCELLED);return false;}
    const auto key=LowerAscii(path);
    const bool temporary=key.size()>=5&&key.compare(key.size()-5,5,L".part")==0;
    auto* session=g_hashReads;
    if(session&&!temporary){const auto hit=session->proofs.find(key);if(hit!=session->proofs.end()){
        ++session->hits;hex=hit->second->digest;return true;
    }}
    auto proof=std::make_unique<HashReadProof>();
    if(!LockRegularFile(path,proof->locks))return false;
    const auto began=GetTickCount64();
    const bool ok=GetOpenFileSha256Hex(proof->locks.handles.back(),hex);
    if(session){++session->diskReads;session->hashMs+=GetTickCount64()-began;}
    if(!ok)return false;
    if(session&&!temporary&&session->proofs.size()<1024){proof->digest=hex;session->proofs.emplace(key,std::move(proof));}
    return true;
}

static bool ExpectedPayloadHash(int itemIndex, std::wstring& expected, std::wstring& error);

static bool VerifyPinnedPayloadForItem(int itemIndex, const std::wstring& path,
                                       std::wstring& error,HANDLE alreadyOpen=INVALID_HANDLE_VALUE) {
    error.clear();
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) {
        error = L"Некорректный индекс программы.";
        return false;
    }

    if (!HasPinnedSha256(itemIndex)) {
        error = L"Для этой программы не задан проверенный SHA-256. Загрузка и запуск отключены.";
        return false;
    }
    std::wstring expected;
    if (!ExpectedPayloadHash(itemIndex, expected, error)) { (void)0; return false; }

    std::wstring actual;
    const auto hashStart=GetTickCount64();
    const bool hashOk=alreadyOpen==INVALID_HANDLE_VALUE?GetFileSha256Hex(path,actual):GetOpenFileSha256Hex(alreadyOpen,actual);
    if(alreadyOpen!=INVALID_HANDLE_VALUE&&g_hashReads){++g_hashReads->diskReads;g_hashReads->hashMs+=GetTickCount64()-hashStart;}
    if (!hashOk) {
        error = g_cancelRequested.load()?L"Операция отменена.":L"Не удалось вычислить SHA-256 загруженного файла.";
        return false;
    }
    (void)0;
    if (_wcsicmp(actual.c_str(), expected.c_str()) != 0) {
        error = L"SHA-256 не совпадает с доверенным каталогом. Запуск заблокирован. Для обновляемого источника нужен актуальный подписанный манифест и настроенный доверенный ключ; для фиксированной версии — проверенный пакет/выпуск HolyCheck.";
        return false;
    }
    return true;
}

#include "11_signed_updates.inc"
