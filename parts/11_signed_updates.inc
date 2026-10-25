#include "update_trust_config.h"

static bool HashBytes(const BYTE* data, DWORD count, std::wstring& hex) {
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0; hex.clear();
    CryptoScope crypto{provider, hash};
    bool ok = CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) && CryptHashData(hash, data, count, 0);
    BYTE digest[32]{}; DWORD n = sizeof(digest);
    if (ok) ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &n, 0) && n == sizeof(digest);
    if (ok) for (BYTE b : digest) {
        static const wchar_t digits[] = L"0123456789abcdef";
        hex += digits[b >> 4]; hex += digits[b & 15];
    }
    return ok;
}

struct UpdateState { uint64_t sequence = 0, lastTime = 0; std::wstring digest; };
static bool LoadUpdateState(UpdateState& state, bool& exists, const wchar_t* registryPath = L"Software\\HolyCheck\\UpdateTrust") {
    state = {}; exists = false;
    HKEY key = nullptr;
    LONG status = RegOpenKeyExW(HKEY_CURRENT_USER, registryPath, 0, KEY_QUERY_VALUE, &key);
    if (status == ERROR_FILE_NOT_FOUND) return true;
    if (status != ERROR_SUCCESS) return false;
    DWORD type = 0, n = 0;
    status = RegQueryValueExW(key, L"State", nullptr, &type, nullptr, &n);
    if (status == ERROR_FILE_NOT_FOUND) { RegCloseKey(key); return true; }
    if (status != ERROR_SUCCESS || type != REG_BINARY || !n || n > 65536) { RegCloseKey(key); return false; }
    std::vector<BYTE> encrypted(n); const DWORD capacity = n;
    status = RegQueryValueExW(key, L"State", nullptr, &type, encrypted.data(), &n); RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_BINARY || n > capacity) return false;
    DATA_BLOB in{n, encrypted.data()}, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    const std::string text(reinterpret_cast<char*>(out.pbData), out.cbData); LocalFree(out.pbData);
    const auto a = text.find('\n'), b = a == std::string::npos ? a : text.find('\n', a + 1);
    if (a == std::string::npos || b == std::string::npos ||
        !HolyManifest::Number(text.substr(0, a), state.sequence) || !state.sequence ||
        !HolyManifest::Number(text.substr(a + 1, b - a - 1), state.lastTime) ||
        !HolyManifest::Hex(text.substr(b + 1))) return false;
    if (!HolyManifest::ToWideAscii(text.substr(b + 1), state.digest)) return false;
    exists = true; return true;
}
static bool SaveUpdateState(const UpdateState& state, const wchar_t* registryPath = L"Software\\HolyCheck\\UpdateTrust") {
    std::string hash;
    if (!state.sequence || !HolyManifest::ToAscii(state.digest, hash) || !HolyManifest::Hex(hash)) return false;
    const auto text = std::to_string(state.sequence) + "\n" + std::to_string(state.lastTime) + "\n" + hash;
    DATA_BLOB in{static_cast<DWORD>(text.size()), reinterpret_cast<BYTE*>(const_cast<char*>(text.data()))}, out{};
    if (!CryptProtectData(&in, L"HolyCheck update state", nullptr, nullptr, nullptr,
                         CRYPTPROTECT_UI_FORBIDDEN, &out)) return false;
    HKEY key = nullptr;
    bool ok = RegCreateKeyExW(HKEY_CURRENT_USER, registryPath, 0, nullptr, 0,
        KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS;
    if (ok) {
        ok = RegSetValueExW(key, L"State", 0, REG_BINARY, out.pbData, out.cbData) == ERROR_SUCCESS;
        if (ok) ok = RegFlushKey(key) == ERROR_SUCCESS;
        RegCloseKey(key);
    }
    LocalFree(out.pbData); return ok;
}

static bool VerifyCmsManifest(const std::vector<BYTE>& signedBytes, std::string& body, std::wstring& error, const wchar_t* pinnedKey) {
    error = L"Подпись манифеста обновлений не прошла проверку.";
    if (!IsSha256(pinnedKey) || signedBytes.empty() || signedBytes.size() > 1024 * 1024) return false;
    // Require a single signer and SHA-256, not SHA-1/MD5 even for a pinned key.
    HCRYPTMSG msg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, nullptr, nullptr);
    if (!msg) return false;
    DWORD signers = 0, n = sizeof(signers), infoBytes = 0;
    bool ok = CryptMsgUpdate(msg, signedBytes.data(), static_cast<DWORD>(signedBytes.size()), TRUE) &&
        CryptMsgGetParam(msg, CMSG_SIGNER_COUNT_PARAM, 0, &signers, &n) && signers == 1 &&
        CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &infoBytes) && infoBytes && infoBytes <= 65536;
    std::vector<BYTE> info(ok ? infoBytes : 0);
    if (ok) ok = CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, info.data(), &infoBytes) &&
        reinterpret_cast<CMSG_SIGNER_INFO*>(info.data())->HashAlgorithm.pszObjId &&
        std::strcmp(reinterpret_cast<CMSG_SIGNER_INFO*>(info.data())->HashAlgorithm.pszObjId, szOID_NIST_sha256) == 0;
    CryptMsgClose(msg);
    if (!ok) return false;
    CRYPT_VERIFY_MESSAGE_PARA parameters{};
    parameters.cbSize = sizeof(parameters); parameters.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    DWORD contentBytes = 0;
    if (!CryptVerifyMessageSignature(&parameters, 0, signedBytes.data(), static_cast<DWORD>(signedBytes.size()),
                                    nullptr, &contentBytes, nullptr) || !contentBytes || contentBytes > 65536) return false;
    std::vector<BYTE> content(contentBytes); PCCERT_CONTEXT signer = nullptr;
    ok = CryptVerifyMessageSignature(&parameters, 0, signedBytes.data(), static_cast<DWORD>(signedBytes.size()),
                                     content.data(), &contentBytes, &signer) != FALSE;
    BYTE* spki = nullptr; DWORD spkiBytes = 0; std::wstring hash;
    if (ok && signer) ok = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
        &signer->pCertInfo->SubjectPublicKeyInfo, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &spki, &spkiBytes) &&
        HashBytes(spki, spkiBytes, hash) && _wcsicmp(hash.c_str(), pinnedKey) == 0;
    else ok = false;
    if (spki) LocalFree(spki);
    if (signer) CertFreeCertificateContext(signer);
    if (!ok) return false;
    body.assign(reinterpret_cast<char*>(content.data()), contentBytes); return true;
}

static bool FetchSignedUpdateManifest(std::vector<BYTE>& bytes, std::wstring& error);

static bool ExpectedPayloadHash(int itemIndex, std::wstring& expected, std::wstring& error) {
    expected.clear();
    if(itemIndex<0||static_cast<size_t>(itemIndex)>=kItemCount||kItems[itemIndex].website) {
        error=L"Некорректный элемент каталога загрузок.";return false;
    }
    // A signed update must not silently re-enable a catalog entry suspended
    // after an incident. Re-enabling requires a reviewed catalog release.
    if(RejectReportedPayload(itemIndex,error))return false;
    expected = PayloadPins()[static_cast<size_t>(itemIndex)];
    if (!kItems[itemIndex].rolling) return true; // Fixed version: exact compiled hash.
    static std::mutex mutex;
    std::lock_guard<std::mutex> guard(mutex);
    UpdateState state; bool stateExists = false;
    if (!LoadUpdateState(state, stateExists)) { error = L"Повреждено/недоступно состояние защиты от отката."; return false; }
    const bool remote = HolyUpdateConfig::kManifestUrl[0] != 0;
    if (!IsSha256(HolyUpdateConfig::kSignerSpkiSha256)) {
        if (HolyUpdateConfig::kSignerSpkiSha256[0] != 0 || remote || stateExists) {
            error = L"Не настроен доверенный ключ подписанного каталога. Возврат к встроенным хешам запрещён."; return false;
        }
        // Undeployed builds retain ONLY exact original pins, never learn hashes.
        static bool warned = false;
        if (!warned) { (void)0; warned = true; }
        return true;
    }
    struct MetadataCache { std::vector<BYTE> bytes; ULONGLONG fetched = 0; };
    static MetadataCache cache;
    std::vector<BYTE> bytes;
    bool fetchedRemote = false;
    if (remote) {
        // Reuse verified signed bytes for at most 60 seconds. Signature, freshness
        // and rollback state are rechecked on EVERY use, even while cached.
        if (!cache.bytes.empty() && GetTickCount64() - cache.fetched < 60000) bytes = cache.bytes;
        else {
            if (!FetchSignedUpdateManifest(bytes, error)) { cache = {}; return false; }
            fetchedRemote = true;
        }
    } else {
        // Explicit offline deployment; once a key is provisioned a missing
        // manifest is an error, never permission to fall back to baseline pins.
        const auto path = JoinPath(g_appDir, L"updates.p7m");
        HandleSet locks;
        if (!LockRegularFile(path, locks)) { error = L"Подписанный каталог отсутствует или недоступен."; return false; }
        const HANDLE file = locks.handles.back(); LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 1024 * 1024) {
            error = L"Некорректный размер манифеста."; return false;
        }
        bytes.resize(static_cast<size_t>(size.QuadPart)); DWORD got = 0;
        if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr) || got != bytes.size()) {
            error = L"Не удалось прочитать подписанный каталог."; return false;
        }
    }
    std::string body;
    if (!VerifyCmsManifest(bytes, body, error, HolyUpdateConfig::kSignerSpkiSha256)) return false;
    HolyManifest::Document doc;
    if (!HolyManifest::Parse(body, doc)) { error = L"Некорректный формат подписанного манифеста."; return false; }
    const time_t rawNow = time(nullptr);
    if (rawNow < 0 || !HolyManifest::Fresh(doc, static_cast<uint64_t>(rawNow), HolyUpdateConfig::kMinimumSequence,
                                         state.sequence, state.lastTime)) {
        error = L"Манифест просрочен, из будущего, имеет старую версию либо часы переведены назад."; return false;
    }
    std::vector<std::string> catalogue;
    for (const auto& item : kItems) if (item.rolling) {
        std::string name;
        if (!HolyManifest::ToAscii(item.file, name)) {
            error = L"Имя файла каталога не представимо в ASCII-формате манифеста."; return false;
        }
        catalogue.push_back(name);
    }
    if (!HolyManifest::MatchesCatalogue(doc, catalogue)) {
        error = L"Подписанный каталог не соответствует полному списку обновляемых загрузок."; return false;
    }
    std::wstring digest;
    if (!HashBytes(reinterpret_cast<const BYTE*>(body.data()), static_cast<DWORD>(body.size()), digest)) return false;
    if (stateExists && !HolyManifest::Consistent(doc.sequence, state.sequence, digest, state.digest)) {
        error = L"Содержимое манифеста изменено без увеличения версии."; return false;
    }
    UpdateState next{doc.sequence, std::max(state.lastTime, static_cast<uint64_t>(rawNow)), digest};
    if ((!stateExists || next.sequence != state.sequence || next.lastTime != state.lastTime || next.digest != state.digest) &&
        !SaveUpdateState(next)) { error = L"Не удалось сохранить защиту от отката; обновление заблокировано."; return false; }
    std::string fileName;
    if (!HolyManifest::ToAscii(kItems[itemIndex].file, fileName)) {
        error = L"Имя файла каталога не представимо в ASCII-формате манифеста."; return false;
    }
    const auto& value = doc.hashes.at(fileName);
    if (!HolyManifest::ToWideAscii(value, expected)) {
        error = L"Хеш в манифесте содержит недопустимые символы."; return false;
    }
    if (fetchedRemote) {
        cache.bytes = std::move(bytes); cache.fetched = GetTickCount64();
        (void)0;
    }
    return true;
}
