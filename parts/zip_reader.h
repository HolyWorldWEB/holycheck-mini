#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <set>
#include <string>
#include <vector>
#include "raw_deflate.h"

// Bounded ZIP32/ZIP64 entry sizes: fail closed for encryption, split archives, links and unknown
// compression. Reader bounds are checked before every read. No extraction API
// is ever given an unvalidated archive pathname.
namespace HolyZip {
using Read = std::function<bool(uint64_t, void*, size_t)>;
using Write = std::function<bool(const unsigned char*, size_t)>;
inline uint16_t U16(const unsigned char* p) { return uint16_t(p[0] | (unsigned(p[1]) << 8)); }
inline uint32_t U32(const unsigned char* p) { return uint32_t(U16(p)) | (uint32_t(U16(p + 2)) << 16); }
struct Entry {
    std::string name;
    uint64_t data = 0;
    uint32_t compressed = 0, size = 0, crc = 0;
    uint16_t method = 0, flags = 0;
    bool directory = false;
};
inline bool SafeName(const std::string& name) {
    if (name.empty() || name.size() > 2048 || name.front() == '/') return false;
    size_t start = 0; unsigned depth = 0;
    while (start < name.size()) {
        size_t end = name.find('/', start);
        if (end == std::string::npos) end = name.size();
        std::string part = name.substr(start, end - start);
        if (++depth > 16 || part.empty() || part == "." || part == ".." ||
            part.back() == '.' || part.back() == ' ') return false;
        for (unsigned char c : part)
            if (c < 32 || c == 127 || c == '\\' || c == ':' || c == '*' || c == '?' ||
                c == '"' || c == '<' || c == '>' || c == '|') return false;
        std::string stem = part.substr(0, part.find('.'));
        while (!stem.empty() && (stem.back() == ' ' || stem.back() == '.')) stem.pop_back();
        for (char& c : stem) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
        if (stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" ||
            stem == "conin$" || stem == "conout$" ||
            (stem.size() == 4 && (stem.substr(0, 3) == "com" || stem.substr(0, 3) == "lpt") &&
             stem[3] >= '0' && stem[3] <= '9')) return false;
        start = end + 1;
    }
    return true;
}
// ZIP64 can be used even for small files (e.g. streaming .NET ZIP writers).
// Decode only fields whose 32-bit counterparts are sentinels, in APPNOTE order.
inline bool Zip64Fields(const std::vector<unsigned char>& extra, uint64_t& size,
                        uint64_t& compressed, uint64_t& local) {
    bool seen = false;
    const bool needSize = size == UINT32_MAX, needCompressed = compressed == UINT32_MAX,
               needLocal = local == UINT32_MAX;
    for (size_t p = 0; p < extra.size();) {
        if (extra.size() - p < 4) return false;
        const unsigned tag = U16(extra.data() + p), n = U16(extra.data() + p + 2);
        p += 4;
        if (n > extra.size() - p) return false;
        if (tag == 1) {
            if (seen) return false;
            seen = true; size_t q = p;
            auto take = [&](uint64_t& value) {
                if (p + n - q < 8) return false;
                value = uint64_t(U32(extra.data() + q)) | (uint64_t(U32(extra.data() + q + 4)) << 32);
                q += 8; return true;
            };
            if ((needSize && !take(size)) || (needCompressed && !take(compressed)) ||
                (needLocal && !take(local))) return false;
        }
        p += n;
    }
    return (!(needSize || needCompressed || needLocal) || seen) &&
           size <= 2ULL * 1024 * 1024 * 1024 && compressed <= 2ULL * 1024 * 1024 * 1024 &&
           local <= 2ULL * 1024 * 1024 * 1024;
}
inline bool Parse(const Read& raw, uint64_t length, std::vector<Entry>& entries) {
    entries.clear();
    if (length < 22 || length > 2ULL * 1024 * 1024 * 1024) return false;
    auto read = [&](uint64_t at, void* dst, size_t n) {
        return at <= length && n <= length - at && raw(at, dst, n);
    };
    const size_t count = size_t(std::min<uint64_t>(length, 65557));
    std::vector<unsigned char> tail(count);
    if (!read(length - count, tail.data(), count)) return false;
    size_t eocd = count;
    for (size_t i = count - 22;; --i) {
        if (U32(tail.data() + i) == 0x06054b50 && i + 22 + U16(tail.data() + i + 20) == count) {
            eocd = i; break;
        }
        if (!i) break;
    }
    if (eocd == count) return false;
    const auto* e = tail.data() + eocd;
    const unsigned files = U16(e + 10);
    const uint64_t central = U32(e + 16), centralSize = U32(e + 12);
    if (U16(e + 4) || U16(e + 6) || files != U16(e + 8) || !files || files > 10000 ||
        central > length || centralSize > length - central ||
        central + centralSize != length - count + eocd) return false;
    uint64_t pos = central, expanded = 0;
    std::set<std::string> names;
    std::vector<std::pair<uint64_t, uint64_t>> ranges;
    for (unsigned i = 0; i < files; ++i) {
        unsigned char h[46]{};
        if (pos > central + centralSize || sizeof(h) > central + centralSize - pos ||
            !read(pos, h, sizeof(h)) || U32(h) != 0x02014b50) return false;
        Entry item;
        item.flags = U16(h + 8); item.method = U16(h + 10);
        item.crc = U32(h + 16); item.compressed = U32(h + 20); item.size = U32(h + 24);
        const size_t nameLength = U16(h + 28), extra = U16(h + 30), comment = U16(h + 32);
        const uint64_t recordSize = 46 + nameLength + extra + comment;
        uint64_t local = U32(h + 42), fullSize = item.size, fullCompressed = item.compressed;
        const unsigned mode = (U32(h + 38) >> 16) & 0170000;
        if ((item.flags & ~uint16_t(0x080e)) || (item.method != 0 && item.method != 8) ||
            U16(h + 34) || (mode && mode != 0100000 && mode != 0040000) ||
            (U32(h + 38) & 0x400) || !nameLength || nameLength > 2048 ||
            recordSize > central + centralSize - pos) return false;
        std::vector<unsigned char> extraBytes(extra);
        if ((extra && !read(pos + 46 + nameLength, extraBytes.data(), extra)) ||
            !Zip64Fields(extraBytes, fullSize, fullCompressed, local) || local >= central) return false;
        item.size = static_cast<uint32_t>(fullSize);
        item.compressed = static_cast<uint32_t>(fullCompressed);
        item.name.resize(nameLength);
        if (!read(pos + 46, &item.name[0], nameLength) || !SafeName(item.name)) return false;
        // Non-ASCII names must explicitly be UTF-8. Decoding is checked by the
        // Windows wrapper; OEM guessing would introduce ambiguous filenames.
        for (unsigned char c : item.name) if (c >= 128 && !(item.flags & 0x800)) return false;
        item.directory = item.name.back() == '/';
        if ((mode == 0040000 || (U32(h + 38) & 0x10)) && !item.directory) return false;
        if (item.directory && item.size) return false;
        std::string key = item.name;
        for (char& c : key) if (c >= 'A' && c <= 'Z') c = char(c - 'A' + 'a');
        if (item.directory) key.pop_back();
        if (!names.insert(key).second) return false;
        unsigned char l[30]{};
        if (central - local < sizeof(l) || !read(local, l, sizeof(l)) || U32(l) != 0x04034b50 ||
            U16(l + 6) != item.flags || U16(l + 8) != item.method || U16(l + 26) != nameLength) return false;
        if (!(item.flags & 8)) {
            uint64_t localSize = U32(l + 22), localCompressed = U32(l + 18), unusedOffset = 0;
            const size_t localExtraSize = U16(l + 28);
            std::vector<unsigned char> localExtra(localExtraSize);
            const uint64_t localExtraAt = local + 30 + nameLength;
            if (localExtraAt > central || localExtraSize > central - localExtraAt ||
                (localExtraSize && !read(localExtraAt, localExtra.data(), localExtraSize)) ||
                !Zip64Fields(localExtra, localSize, localCompressed, unusedOffset) ||
                U32(l + 14) != item.crc || localCompressed != item.compressed || localSize != item.size) return false;
        }
        item.data = local + 30 + nameLength + U16(l + 28);
        if (item.data > central || item.compressed > central - item.data) return false;
        std::string localName(nameLength, '\0');
        if (!read(local + 30, &localName[0], nameLength) || localName != item.name) return false;
        ranges.emplace_back(local, item.data + item.compressed);
        expanded += item.size;
        if (expanded > 4ULL * 1024 * 1024 * 1024 || item.size > 2ULL * 1024 * 1024 * 1024) return false;
        entries.push_back(item); pos += recordSize;
    }
    if (pos != central + centralSize) return false;
    std::sort(ranges.begin(), ranges.end());
    for (size_t i = 1; i < ranges.size(); ++i) if (ranges[i].first < ranges[i - 1].second) return false;
    return true;
}

inline bool Expand(const Read& read, const Entry& entry, const Write& write) {
    if (entry.method == 8)
        return HolyDeflate::Expand(read, entry.data, entry.compressed,
                                   entry.size, entry.crc, write);
    if (entry.method != 0 || entry.compressed != entry.size) return false;
    std::array<unsigned char, 65536> buffer{};
    uint64_t consumed = 0;
    uint32_t crc = 0;
    while (consumed < entry.compressed) {
        const size_t n = static_cast<size_t>(std::min<uint64_t>(buffer.size(), entry.compressed - consumed));
        if (!read(entry.data + consumed, buffer.data(), n) || !write(buffer.data(), n)) return false;
        crc = HolyDeflate::Crc32(crc, buffer.data(), n);
        consumed += n;
    }
    return crc == entry.crc;
}
} // namespace HolyZip
