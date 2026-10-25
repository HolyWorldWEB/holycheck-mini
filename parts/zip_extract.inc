struct TrustedExtractedFile { std::wstring path, sha256; };
static std::mutex g_extractedMutex;
static std::array<std::vector<TrustedExtractedFile>, kItemCount> g_extractedFiles;
static std::array<std::wstring, kItemCount> g_inventoryArchiveHash;
static std::array<std::wstring, kItemCount> g_inventoryExtractionRoot;

static std::wstring ExtractPathKey(std::wstring path) {
    if (!path.empty()) CharUpperBuffW(&path[0], static_cast<DWORD>(path.size()));
    return path;
}
static bool ReadAt(HANDLE file, uint64_t offset, void* buffer, size_t size) {
    if (size > MAXDWORD || offset > static_cast<uint64_t>(INT64_MAX)) return false;
    LARGE_INTEGER at{}; at.QuadPart = static_cast<LONGLONG>(offset); DWORD count = 0;
    return SetFilePointerEx(file, at, nullptr, FILE_BEGIN) &&
           ReadFile(file, buffer, static_cast<DWORD>(size), &count, nullptr) && count == size;
}
static bool ArchivePlan(int itemIndex, const HolyZip::Read& read, uint64_t size,
                        std::vector<HolyZip::Entry>& entries, std::vector<std::wstring>& names,
                        std::wstring& error,const std::wstring& destination=L"",bool legacyFlat=false) {
    if(itemIndex<0||static_cast<size_t>(itemIndex)>=kItemCount) {
        error=L"ZIP: неизвестная программа.";return false;
    }
    const auto root=destination.empty()?ItemExtractDirectory(itemIndex):destination;
    if(!HolyFiles::LocalPath(root)) {error=L"ZIP: недопустимый каталог распаковки.";return false;}
    FullLog(L"ZIP parse item=" + std::to_wstring(itemIndex) + L" bytes=" + std::to_wstring(size));
    if (!HolyZip::Parse(read, size, entries)) {
        error = L"ZIP: недопустимые заголовки/пути либо неподдерживаемый формат."; return false;
    }
    FullLog(L"ZIP entries=" + std::to_wstring(entries.size()));
    std::set<std::wstring> keys;
    for (const auto& entry : entries) {
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, entry.name.data(),
                                             static_cast<int>(entry.name.size()), nullptr, 0);
        if (count <= 0) { error = L"ZIP: имя не является корректным UTF-8."; return false; }
        std::wstring name(static_cast<size_t>(count), L'\0');
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, entry.name.data(),
                                static_cast<int>(entry.name.size()), &name[0], count)) return false;
        std::replace(name.begin(), name.end(), L'/', L'\\');
        if (entry.directory) name.pop_back();
        if (legacyFlat&&!entry.directory) name = HolyStorage::RelativeName(kItems[itemIndex].name, name);
        for (size_t start = 0; start < name.size();) {
            const auto end = name.find(L'\\', start);
            if (!IsSimpleFileName(name.substr(start, end == std::wstring::npos ? end : end - start))) {
                error = L"ZIP: небезопасное имя записи: " + name; return false;
            }
            if (end == std::wstring::npos) break;
            start = end + 1;
        }
        const auto full = JoinPath(root, name);
        if (full.size() >= MAX_PATH - 12 || !keys.insert(ExtractPathKey(full)).second) {
            error = L"ZIP: слишком длинный путь либо конфликт имён."; return false;
        }
        for (size_t other = 0; other < kItemCount; ++other)
            if (ExtractPathKey(full) == ExtractPathKey(ItemPath(static_cast<int>(other)))) {
                error = L"ZIP пытается заменить файл загрузки из каталога программ."; return false;
            }
        names.push_back(full);
    }
    return true;
}
static bool HashArchiveEntry(const HolyZip::Read& read, const HolyZip::Entry& entry,
                              std::wstring& hex, std::wstring& error) {
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0; CryptoScope crypto{provider, hash};
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) return false;
    if (!HolyZip::Expand(read, entry, [&](const unsigned char* data, size_t n) {
        return !g_cancelRequested.load() && n <= MAXDWORD && CryptHashData(hash, data, static_cast<DWORD>(n), 0);
    })) { error = L"ZIP: ошибка декомпрессии/CRC или операция отменена."; return false; }
    BYTE digest[32]{}; DWORD n = sizeof(digest);
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &n, 0) || n != sizeof(digest)) return false;
    hex.clear(); static constexpr wchar_t digits[] = L"0123456789abcdef";
    for (BYTE b : digest) { hex += digits[b >> 4]; hex += digits[b & 15]; }
    return true;
}
// Reconstruct trust from the pinned archive, not a writable on-disk inventory.
static bool LoadArchiveInventory(int itemIndex, std::wstring& error) {
    const auto inventoryStarted=GetTickCount64();
    HandleSet locks; const auto path = ItemPath(itemIndex);
    const auto extractionRoot=ExtractPathKey(ItemExtractDirectory(itemIndex));
    if (!LockRegularFile(path, locks) || !VerifyPinnedPayloadForItem(itemIndex, path, error)) { FullLog(L"ZIP inventory failed item=" + std::to_wstring(itemIndex) + L" code=" + std::to_wstring(GetLastError()) + L" reason=" + error); return false; }
    std::wstring expected;
    if (!ExpectedPayloadHash(itemIndex, expected, error)) return false;
    {
        std::lock_guard<std::mutex> guard(g_extractedMutex);
        if (g_inventoryArchiveHash[itemIndex] == expected && g_inventoryExtractionRoot[itemIndex]==extractionRoot && !g_extractedFiles[itemIndex].empty()) return true;
    }
    const HANDLE archive = locks.handles.back(); LARGE_INTEGER size{};
    if (!GetFileSizeEx(archive, &size) || size.QuadPart < 0) return false;
    auto read = [&](uint64_t offset, void* data, size_t n) {
        return offset <= static_cast<uint64_t>(size.QuadPart) && n <= static_cast<uint64_t>(size.QuadPart) - offset &&
               ReadAt(archive, offset, data, n);
    };
    std::vector<HolyZip::Entry> entries; std::vector<std::wstring> names;
    if (!ArchivePlan(itemIndex, read, static_cast<uint64_t>(size.QuadPart), entries, names, error)) return false;
    std::vector<TrustedExtractedFile> files;uint64_t expandedBytes=0;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (g_cancelRequested.load()) { error = L"Операция отменена."; return false; }
        std::wstring hash;
        if (!HashArchiveEntry(read, entries[i], hash, error)) return false;
        if (!entries[i].directory) {files.push_back({names[i], hash});expandedBytes+=entries[i].size;}
    }
    if (files.empty()) { error = L"ZIP не содержит файлов."; return false; }
    FullLog(L"ZIP inventory decoded item="+std::to_wstring(itemIndex)+L" totalMs="+
        std::to_wstring(GetTickCount64()-inventoryStarted)+L" expandedBytes="+std::to_wstring(expandedBytes));
    std::lock_guard<std::mutex> guard(g_extractedMutex);
    g_extractedFiles[itemIndex] = std::move(files); g_inventoryArchiveHash[itemIndex] = expected;
    g_inventoryExtractionRoot[itemIndex]=extractionRoot;
    return true;
}
// Readiness hint only: LoadArchiveInventory must precede this call. Existence
// never authorises a launch: OpenTrackedPath rehashes and locks every own file
// and checks the shared namespace before ShellExecute.
static bool HaveArchiveFilesOnDisk(int itemIndex) {
    if(itemIndex<0||static_cast<size_t>(itemIndex)>=kItemCount||g_cancelRequested.load())return false;
    std::vector<TrustedExtractedFile> own;
    {std::lock_guard<std::mutex> guard(g_extractedMutex);
     if(g_inventoryArchiveHash[itemIndex].empty())return false;
     own=g_extractedFiles[itemIndex];}
    return !own.empty()&&std::all_of(own.begin(),own.end(),[](const auto& f){return !g_cancelRequested.load()&&FileExists(f.path);});
}
// Read-only v13 compatibility. Buttons now belong to ss, but old verified
// files must not become "unknown EXEs" that block the previous shared tab.
// No old file is deleted, globally trusted by name, or selected as a new target.
static bool CollectPreviousSsExpected(int tab,HandleSet& locks,std::map<std::wstring,std::wstring>& expected,
                                     std::set<std::wstring>& downloaded,std::wstring& error) {
    if(tab!=3)return true;
    // Cache derived HASH STRINGS only, never trust an unverified pathname or
    // retain handles between operations. Revalidate the anchor before reuse.
    static std::mutex cacheMutex;
    static std::array<std::wstring,kItemCount> cacheKeys;
    static std::array<std::map<std::wstring,std::wstring>,kItemCount> cacheFiles;
    const auto oldDirectory=HolyStorage::TabPath(g_appDir,3);
    for(int i=0;i<static_cast<int>(kItemCount);++i) {
        if(!HolyStorage::MovedToSs(kItems[i].name))continue;
        const auto oldPayload=JoinPath(oldDirectory,kItems[i].file);
        const bool oldPresent=FileExists(oldPayload);
        if(oldPresent) {
            if(!LockRegularFile(oldPayload,locks)||!VerifyPinnedPayloadForItem(i,oldPayload,error))return false;
            downloaded.insert(ExtractPathKey(oldPayload));
        }
        const std::wstring file(kItems[i].file);
        if(HolyStorage::ArchiveFolderName(file).empty())continue;
        const auto anchor=oldPresent?oldPayload:ItemPath(i);
        if(!FileExists(anchor))continue;
        if(!LockRegularFile(anchor,locks)||!VerifyPinnedPayloadForItem(i,anchor,error))return false;
        std::wstring pin;if(!ExpectedPayloadHash(i,pin,error))return false;
        const auto cacheKey=ExtractPathKey(oldDirectory)+L"|"+pin;
        {
            std::lock_guard<std::mutex> guard(cacheMutex);
            if(cacheKeys[i]==cacheKey&&!cacheFiles[i].empty()) {
                for(const auto& file:cacheFiles[i])if(!HolyStorage::MergeFile(expected,file.first,file.second)) {
                    error=L"Конфликт прежних файлов перенесённой программы.";return false;
                }
                continue;
            }
        }
        const HANDLE archive=locks.handles.back();LARGE_INTEGER size{};
        if(!GetFileSizeEx(archive,&size)||size.QuadPart<0)return false;
        auto read=[&](uint64_t offset,void* data,size_t count) {
            return offset<=static_cast<uint64_t>(size.QuadPart)&&count<=static_cast<uint64_t>(size.QuadPart)-offset&&
                ReadAt(archive,offset,data,count);
        };
        std::vector<HolyZip::Entry> entries;std::vector<std::wstring> names;
        if(!ArchivePlan(i,read,static_cast<uint64_t>(size.QuadPart),entries,names,error,oldDirectory,true))return false;
        std::map<std::wstring,std::wstring> derived;
        for(size_t n=0;n<entries.size();++n) {
            if(entries[n].directory)continue;
            std::wstring hash;
            if(!HashArchiveEntry(read,entries[n],hash,error)||!HolyStorage::MergeFile(expected,ExtractPathKey(names[n]),hash)) {
                if(error.empty())error=L"Конфликт прежних файлов перенесённой программы.";
                return false;
            }
            derived.emplace(ExtractPathKey(names[n]),hash);
        }
        {std::lock_guard<std::mutex> guard(cacheMutex);cacheKeys[i]=cacheKey;cacheFiles[i]=std::move(derived);}
    }
    return true;
}
static bool CollectTabExpected(int tab, HandleSet& locks, std::map<std::wstring, std::wstring>& expected,
                                std::set<std::wstring>& downloaded, std::wstring& error) {
    for (int i = 0; i < static_cast<int>(kItemCount); ++i) {
        if (kItems[i].tab != tab || !FileExists(ItemPath(i))) continue;
        if (g_cancelRequested.load()) { error = L"Операция отменена."; return false; }
        const auto path = ItemPath(i);
        if (!LockRegularFile(path, locks) || !VerifyPinnedPayloadForItem(i, path, error)) { FullLog(std::wstring(L"TAB payload rejected item=") + kItems[i].name + L" reason=" + error); if (error.empty()) error=L"Недоступен файл загрузки: " + HolyInstalled::Leaf(path); return false; }
        downloaded.insert(ExtractPathKey(path));
        std::wstring filename(kItems[i].file);
        if (HolyStorage::ArchiveFolderName(filename).empty()) continue;
        if (!LoadArchiveInventory(i, error)) return false;
        std::vector<TrustedExtractedFile> own;
        {std::lock_guard<std::mutex> guard(g_extractedMutex);own=g_extractedFiles[i];}
        const auto extractionRoot=ItemExtractDirectory(i);
        for (const auto& f : own) {
            if (!HolyStorage::MergeFile(expected, ExtractPathKey(f.path), f.sha256)) {
                error = L"Конфликт проверенных распакованных файлов. Перезапись чужой программы запрещена.";return false;
            }
            // Read-only upgrade support for v16 and earlier. Existing flat files
            // are NOT launched/moved/deleted. Their expected hash still comes
            // from this pinned ZIP, so they do not become unknown neighbours.
            if(!HolyFiles::StrictChild(f.path,extractionRoot)) {
                error=L"Инвентарь архива не принадлежит отдельной папке программы.";return false;
            }
            const auto relative=f.path.substr(extractionRoot.size()+1);
            const auto legacy=JoinPath(ItemDirectory(i),HolyStorage::RelativeName(kItems[i].name,relative));
            if(FileExists(legacy)&&!HolyStorage::MergeFile(expected,ExtractPathKey(legacy),f.sha256)) {
                error=L"Прежние общие файлы архивов конфликтуют; старые копии сохранены.";return false;
            }
        }
    }
    if(!CollectPreviousSsExpected(tab,locks,expected,downloaded,error))return false;
    // An already downloaded v11 Normal asset must not block the entire shared
    // tab on upgrade. Bind this exception to the previous exact SHA and path.
    for (int i=0;i<static_cast<int>(kItemCount);++i) {
        if(kItems[i].tab!=tab||std::wstring(kItems[i].name)!=L"JournalTrace")continue;
        const auto legacy=JoinPath(ItemDirectory(i),L"JournalTraceNormal.exe");
        if(!FileExists(legacy))continue;
        std::wstring hash;
        if(!LockRegularFile(legacy,locks)||!GetFileSha256Hex(legacy,hash)||
           !HolyFiles::TrustedLegacyJournalTrace(HolyInstalled::Leaf(legacy),hash)||
           !HolyStorage::MergeFile(expected,ExtractPathKey(legacy),hash)) {
            error=L"Старый JournalTraceNormal.exe изменён или недоступен. Запуск заблокирован.";
            return false;
        }
    }
    for (const auto& key : downloaded) if (expected.count(key)) {
        error = L"Распакованный файл конфликтует с файлом загрузки."; return false;
    }
    return true;
}
struct ExtractRollback {
    std::vector<CreatedFileIdentity> created;std::wstring root;
    explicit ExtractRollback(std::wstring directory):root(std::move(directory)){}
    bool committed = false;
    ~ExtractRollback() { if (!committed) for (auto i = created.rbegin(); i != created.rend(); ++i) i->Remove(root); }
};
static bool ExtractVerifiedZip(int itemIndex, const std::wstring& zipPath,
                               const std::wstring& destination, std::wstring& error) {
    const auto extractionStarted=GetTickCount64();
    if (destination != ItemExtractDirectory(itemIndex) || destination == ItemDirectory(itemIndex) || zipPath != ItemPath(itemIndex)) {
        error=L"ZIP: распаковка разрешена только в отдельную папку рядом с архивом.";return false;
    }
    HandleSet locks, dirs; std::map<std::wstring, std::wstring> expected; std::set<std::wstring> downloaded;
    if (!LockDirectoryChain(destination, dirs, true) ||
        !CollectTabExpected(kItems[itemIndex].tab, locks, expected, downloaded, error)) return false;
    // The archive handle stays pinned until extraction finishes.
    HandleSet archiveLocks;
    if (!LockRegularFile(zipPath, archiveLocks) || !VerifyPinnedPayloadForItem(itemIndex, zipPath, error)) return false;
    const HANDLE archive = archiveLocks.handles.back(); LARGE_INTEGER size{};
    if (!GetFileSizeEx(archive, &size) || size.QuadPart < 0) return false;
    auto read = [&](uint64_t offset, void* data, size_t n) {
        return offset <= static_cast<uint64_t>(size.QuadPart) && n <= static_cast<uint64_t>(size.QuadPart) - offset &&
               ReadAt(archive, offset, data, n);
    };
    std::vector<HolyZip::Entry> entries; std::vector<std::wstring> names;
    if (!ArchivePlan(itemIndex, read, static_cast<uint64_t>(size.QuadPart), entries, names, error)) return false;
    ExtractRollback rollback(destination);
    for (size_t i = 0; i < entries.size(); ++i) {
        if (g_cancelRequested.load()) { error = L"Распаковка отменена."; return false; }
        const auto& entry = entries[i]; const auto& path = names[i];
        if (entry.directory) { if (!LockDirectoryChain(path, dirs, true)) return false; continue; }
        const auto hash = expected.find(ExtractPathKey(path));
        if (hash == expected.end()) return false;
        const DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            HandleSet existing; std::wstring actual;
            if (!LockRegularFile(path, existing) || !GetFileSha256Hex(path, actual) || actual != hash->second) {
                error = L"Файл распаковки уже существует и отличается от доверенного архива. Чужие/изменённые файлы не перезаписываются.";
                return false;
            }
            continue; // Reuse an exact verified file, including across restarts.
        }
        if (!LockDirectoryChain(HolyInstalled::Parent(path), dirs, true)) return false;
        HANDLE out = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (out == INVALID_HANDLE_VALUE) { error = L"ZIP: не удалось создать файл. " + Win32ErrorText(GetLastError()); return false; }
        HandleSet output; output.Add(out);
        CreatedFileIdentity identity;
        if(!identity.Capture(path,out)){error=L"ZIP: не удалось получить идентификатор созданного файла.";return false;}
        rollback.created.push_back(identity);
        if (!HolyZip::Expand(read, entry, [&](const unsigned char* data, size_t n) {
            DWORD written = 0;
            return !g_cancelRequested.load() && n <= MAXDWORD &&
                   WriteFile(out, data, static_cast<DWORD>(n), &written, nullptr) && written == n;
        }) || !FlushFileBuffers(out)) { error = L"ZIP: ошибка записи/CRC или операция отменена."; return false; }
    }
    FullLog(L"ZIP extraction committed item=" + std::to_wstring(itemIndex) + L" newFiles=" + std::to_wstring(rollback.created.size())+L" totalMs="+std::to_wstring(GetTickCount64()-extractionStarted));
    rollback.committed = true; error.clear(); return true;
}
static bool CheckExtractedInventory(const std::wstring& directory, const std::map<std::wstring, std::wstring>& expected,
                                    const std::set<std::wstring>& downloaded, HandleSet& locks, std::wstring& error,
                                    unsigned depth = 0) {
    if(g_cancelRequested.load()){error=L"Операция отменена.";return false;}
    if(depth>16){error=L"Превышена безопасная глубина проверки каталога.";return false;}
    WIN32_FIND_DATAW data{}; HANDLE find = FindFirstFileW(JoinPath(directory, L"*").c_str(), &data);
    if (find == INVALID_HANDLE_VALUE) return GetLastError() == ERROR_FILE_NOT_FOUND;
    bool ok = true;
    do {
        if (wcscmp(data.cFileName, L".") == 0 || wcscmp(data.cFileName, L"..") == 0) continue;
        const auto path = JoinPath(directory, data.cFileName); const auto key = ExtractPathKey(path);
        if (g_cancelRequested.load()) {error=L"Операция отменена.";ok=false;break;}
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            // Ignore unrelated data links without following them. Code links are unsafe.
            if(expected.count(key)||HolyFiles::ExecutionArtifact(path)){error=L"Reparse point в пути исполняемого файла: "+HolyInstalled::Leaf(path);ok=false;break;}
            continue;
        }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if(HolyFiles::ExecutionArtifact(path) && !expected.count(key)){error=L"Посторонний каталог перенаправления загрузчика: "+HolyInstalled::Leaf(path);ok=false;break;}
            if (!LockDirectoryChain(path, locks) || !CheckExtractedInventory(path, expected, downloaded, locks, error, depth + 1)) { ok = false; break; }
        } else if (!downloaded.count(key)) {
            const auto known = expected.find(key); std::wstring actual;
            if (known == expected.end() && !HolyFiles::ExecutionArtifact(path)) continue;
            if (known == expected.end() || !LockRegularFile(path, locks) || !GetFileSha256Hex(path, actual) || actual != known->second) {
                if(g_cancelRequested.load()){error=L"Операция отменена.";ok=false;break;}
                const DWORD code=GetLastError();
                error = L"В общей папке вкладки обнаружен посторонний, недоступный или изменённый файл: " + HolyInstalled::Leaf(path) + L". Запуск заблокирован.";
                FullLog(L"TAB reject leaf=" + HolyInstalled::Leaf(path) + L" known=" + std::to_wstring(known!=expected.end()) + L" win32=" + std::to_wstring(code));
                ok = false; break;
            }
        }
    } while (FindNextFileW(find, &data));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES) ok = false;
    FindClose(find); return ok;
}
static bool LockVerifiedExtractedTree(int itemIndex, const std::wstring& launchPath,
                                      HandleSet& locks, std::wstring& error) {
    if (itemIndex < 0 || static_cast<size_t>(itemIndex) >= kItemCount) return false;
    std::unique_lock<std::recursive_mutex> tabGuard(g_tabFileMutex[kItems[itemIndex].tab]);
    std::map<std::wstring, std::wstring> expected; std::set<std::wstring> downloaded;
    if (!CollectTabExpected(kItems[itemIndex].tab, locks, expected, downloaded, error)) return false;
    std::vector<TrustedExtractedFile> own;
    { std::lock_guard<std::mutex> guard(g_extractedMutex); own = g_extractedFiles[itemIndex]; }
    bool found = false;
    auto alreadyVerified=downloaded; // Files whose no-write/no-delete locks stay held until launch.
    for (const auto& f : own) {
        std::wstring actual;
        if (!LockRegularFile(f.path, locks) || !GetFileSha256Hex(f.path, actual) || actual != f.sha256) {
            if(g_cancelRequested.load()){error=L"Операция отменена.";return false;}
            error = L"Распакованный файл программы изменён, недоступен или отсутствует: " + HolyInstalled::Leaf(f.path); FullLog(L"ZIP own file rejected: " + error); return false;
        }
        alreadyVerified.insert(ExtractPathKey(f.path));
        if (_wcsicmp(f.path.c_str(), launchPath.c_str()) == 0) found = true;
    }
    if (!found) { error = L"EXE не принадлежит проверенному архиву этой программы."; return false; }
    return CheckExtractedInventory(ItemDirectory(itemIndex), expected, alreadyVerified, locks, error);
}
