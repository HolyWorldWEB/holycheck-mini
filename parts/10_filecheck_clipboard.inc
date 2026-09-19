static bool ReadHeader(const std::wstring& path, std::vector<unsigned char>& out, size_t bytes = 16) {
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    out.assign(bytes, 0);
    DWORD read = 0;
    BOOL ok = ReadFile(file, out.data(), static_cast<DWORD>(out.size()), &read, nullptr);
    CloseHandle(file);
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

bool BasicPayloadCheck(const std::wstring& path, const std::wstring& fileName) {
    std::vector<unsigned char> head;
    if (!ReadHeader(path, head)) return false;
    if (head.empty()) return false;

    const std::wstring lower = LowerFileName(fileName);
    auto ends = [&](const wchar_t* suffix) {
        const std::wstring s = suffix;
        return lower.size() >= s.size() && lower.compare(lower.size() - s.size(), s.size(), s) == 0;
    };

    if (ends(L".exe")) return StartsWith(head, {0x4D, 0x5A});
    if (ends(L".msi")) return StartsWith(head, {0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1});
    if (ends(L".zip") || ends(L".jar")) {
        return StartsWith(head, {0x50,0x4B,0x03,0x04}) || StartsWith(head, {0x50,0x4B,0x05,0x06}) || StartsWith(head, {0x50,0x4B,0x07,0x08});
    }
    if (ends(L".7z")) return StartsWith(head, {0x37,0x7A,0xBC,0xAF,0x27,0x1C});
    if (ends(L".rar")) return StartsWith(head, {0x52,0x61,0x72,0x21,0x1A,0x07});
    return true;
}

static bool GetFileSha256Hex(const std::wstring& path, std::wstring& hex) {
    hex.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    bool ok = CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES,
                                   CRYPT_VERIFYCONTEXT) != FALSE;
    if (ok) ok = CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) != FALSE;

    std::vector<BYTE> buffer(256 * 1024);
    while (ok) {
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

    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    CloseHandle(file);
    return ok;
}

static bool VerifyPinnedPayloadForItem(int itemIndex, const std::wstring& path,
                                       std::wstring& error) {
    error.clear();
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) {
        error = L"Некорректный индекс программы.";
        return false;
    }

    if (!HasPinnedSha256(itemIndex)) {
        error = L"Для этой программы не задан проверенный SHA-256. Загрузка и запуск отключены.";
        return false;
    }
    const wchar_t* expected = kItems[itemIndex].sha256;

    std::wstring actual;
    if (!GetFileSha256Hex(path, actual)) {
        error = L"Не удалось вычислить SHA-256 загруженного файла.";
        return false;
    }
    if (_wcsicmp(actual.c_str(), expected) != 0) {
        error = L"SHA-256 файла не совпадает с ожидаемым. Файл не будет открыт.";
        return false;
    }
    return true;
}
