#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>
namespace HolyManifest {
// Manifest identifiers and SHA-256 use ASCII, NOT the current Windows code page.
// Validate before explicit narrowing; never truncate Unicode to 8 bits.
inline bool ToAscii(const std::wstring& input, std::string& output) {
    output.clear();
    for (wchar_t ch : input) {
        const uint32_t code = static_cast<uint32_t>(ch);
        if (code == 0 || code > 0x7f) return false;
    }
    output.reserve(input.size());
    for (wchar_t ch : input) output.push_back(static_cast<char>(ch));
    return true;
}
inline bool ToWideAscii(const std::string& input, std::wstring& output) {
    output.clear();
    for (char ch : input) {
        const auto code = static_cast<unsigned char>(ch);
        if (code == 0 || code > 0x7f) return false;
    }
    output.reserve(input.size());
    for (char ch : input) output.push_back(static_cast<wchar_t>(static_cast<unsigned char>(ch)));
    return true;
}
struct Document {
    uint64_t sequence = 0, issued = 0, expires = 0;
    std::map<std::string, std::string> hashes;
};
inline bool Number(const std::string& text, uint64_t& value) {
    if (text.empty() || text.size() > 20 || (text.size() > 1 && text[0] == '0')) return false;
    value = 0;
    for (const unsigned char c : text) {
        if (c < '0' || c > '9' || value > (UINT64_MAX - (c - '0')) / 10) return false;
        value = value * 10 + c - '0';
    }
    return true;
}
inline bool Hex(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
inline bool Parse(const std::string& body, Document& out) {
    out = {};
    if (body.empty() || body.size() > 65536 || body.back() != '\n') return false;
    std::vector<std::string> lines;
    size_t offset = 0;
    while (offset < body.size()) {
        const auto end = body.find('\n', offset);
        if (end == std::string::npos) return false;
        auto line = body.substr(offset, end - offset);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        for (unsigned char c : line) if (c < 32 || c > 126) return false;
        lines.push_back(std::move(line)); offset = end + 1;
        if (lines.size() > 104) return false;
    }
    if (lines.size() < 5 || lines[0] != "HOLYCHECK-MANIFEST-V1" ||
        !Number(lines[1], out.sequence) || !out.sequence ||
        !Number(lines[2], out.issued) || !Number(lines[3], out.expires) ||
        out.expires <= out.issued || out.expires - out.issued > 7 * 86400) return false;
    for (size_t i = 4; i < lines.size(); ++i) {
        const auto sep = lines[i].find(' ');
        if (sep == std::string::npos || !sep) return false;
        const auto name = lines[i].substr(0, sep), hash = lines[i].substr(sep + 1);
        if (name.size() > 200 || name == "." || name == ".." || name.back() == '.' ||
            name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos ||
            !Hex(hash) || !out.hashes.emplace(name, hash).second) return false;
    }
    return !out.hashes.empty();
}
inline bool Fresh(const Document& doc, uint64_t now, uint64_t floor,
                  uint64_t highest, uint64_t lastTime) {
    // Difference-based comparisons avoid unsigned overflow.
    return doc.sequence >= floor && doc.sequence >= highest && now < doc.expires &&
           !(doc.issued > now && doc.issued - now > 300) &&
           !(lastTime > now && lastTime - now > 300);
}
inline bool Consistent(uint64_t sequence, uint64_t highest,
                       const std::wstring& digest, const std::wstring& storedDigest) {
    return sequence > highest || (sequence == highest && digest == storedDigest);
}

// Entire catalogue, no unknown/fixed-version names and no omitted rolling item.
inline bool MatchesCatalogue(const Document& doc, const std::vector<std::string>& names) {
    if (names.empty() || doc.hashes.size() != names.size()) return false;
    std::map<std::string, bool> seen;
    for (const auto& name : names)
        if (!seen.emplace(name, true).second || !doc.hashes.count(name)) return false;
    return true;
}
// A reusable bounded transport sink. False/oversized/empty/partial reads cannot
// leave unverified bytes in the output. The callback checks cancellation/time.
template<class Read> inline bool ReadBounded(Read read, unsigned char* scratch,
    size_t capacity, std::vector<unsigned char>& out) {
    out.clear(); constexpr size_t limit = 1024 * 1024;
    if (!scratch || !capacity || capacity > limit) return false;
    for (;;) {
        size_t got = 0;
        if (!read(scratch, capacity, got) || got > capacity || got > limit - out.size()) {
            out.clear(); return false;
        }
        if (!got) return !out.empty();
        out.insert(out.end(), scratch, scratch + got);
    }
}

}
