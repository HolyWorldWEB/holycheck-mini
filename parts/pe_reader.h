#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <vector>
namespace HolyPe {
enum class Kind { Invalid, MzOnly, Truncated, Exe, Dll };
enum class Problem { None, NotMz, ShortDos, BadOffset, ShortCoff, MissingPe,
    InvalidCoff, ShortOptional, InvalidOptional, ShortSections, InvalidHeaders,
    SectionRange, ReadFailure };
struct Result { Kind kind; Problem problem; };
using Read = std::function<bool(uint64_t, void*, size_t)>;
inline uint16_t U16(const unsigned char* p) { return uint16_t(p[0] | (unsigned(p[1]) << 8)); }
inline uint32_t U32(const unsigned char* p) { return uint32_t(U16(p)) | (uint32_t(U16(p + 2)) << 16); }
inline const wchar_t* ProblemText(Problem problem) {
    switch (problem) {
    case Problem::None: return L"проверка пройдена";
    case Problem::NotMz: return L"нет сигнатуры MZ";
    case Problem::ShortDos: return L"усечён DOS-заголовок";
    case Problem::BadOffset: return L"недопустимое смещение PE-заголовка";
    case Problem::ShortCoff: return L"усечён PE/COFF-заголовок";
    case Problem::MissingPe: return L"есть MZ, но нет сигнатуры PE";
    case Problem::InvalidCoff: return L"некорректные обязательные поля COFF";
    case Problem::ShortOptional: return L"усечён optional header";
    case Problem::InvalidOptional: return L"некорректный optional header";
    case Problem::ShortSections: return L"усечена таблица секций";
    case Problem::InvalidHeaders: return L"некорректный размер заголовков";
    case Problem::SectionRange: return L"секция пересекает реальные заголовки или выходит за файл";
    case Problem::ReadFailure: return L"ошибка чтения файла";
    }
    return L"неизвестная причина";
}
inline Result Inspect(const Read& raw, uint64_t length) {
    bool ioError = false;
    auto read = [&](uint64_t at, void* dst, size_t n) {
        if (at > length || n > length - at) return false;
        if (!raw(at, dst, n)) { ioError = true; return false; }
        return true;
    };
    auto fail = [&](Kind kind, Problem problem) {
        return Result{kind, ioError ? Problem::ReadFailure : problem};
    };
    unsigned char signature[2]{};
    if (!read(0, signature, sizeof(signature)) || U16(signature) != 0x5a4d)
        return fail(Kind::Invalid, Problem::NotMz);
    unsigned char dos[64]{};
    if (!read(0, dos, sizeof(dos))) return fail(Kind::Truncated, Problem::ShortDos);
    const uint64_t nt = U32(dos + 60);
    unsigned char header[24]{};
    if (nt < 2) return fail(Kind::MzOnly, Problem::MissingPe);
    if (nt > INT32_MAX) return fail(Kind::Invalid, Problem::BadOffset);
    if (!read(nt, header, sizeof(header))) return fail(Kind::Truncated, Problem::ShortCoff);
    if (U32(header) != 0x00004550) return fail(Kind::MzOnly, Problem::MissingPe);
    const unsigned sections = U16(header + 6), optSize = U16(header + 20), flags = U16(header + 22);
    if (!U16(header + 4) || !sections || sections > 96 || !(flags & 2) || optSize < 96)
        return fail(Kind::Invalid, Problem::InvalidCoff);
    std::vector<unsigned char> optional(optSize);
    if (!read(nt + 24, optional.data(), optSize)) return fail(Kind::Truncated, Problem::ShortOptional);
    const unsigned magic = U16(optional.data());
    const unsigned dirStart = magic == 0x10b ? 96 : magic == 0x20b ? 112 : 0;
    if (!dirStart || optSize < dirStart ||
        U32(optional.data() + dirStart - 4) > (optSize - dirStart) / 8)
        return fail(Kind::Invalid, Problem::InvalidOptional);
    const uint64_t sectionStart = nt + 24 + optSize;
    const uint64_t sectionEnd = sectionStart + uint64_t(sections) * 40;
    const uint64_t headerSize = U32(optional.data() + 60);
    if (sectionEnd > length) return fail(Kind::Truncated, Problem::ShortSections);
    if (headerSize < sectionEnd || headerSize > length) return fail(Kind::Invalid, Problem::InvalidHeaders);
    for (unsigned i = 0; i < sections; ++i) {
        unsigned char section[40]{};
        if (!read(sectionStart + uint64_t(i) * 40, section, sizeof(section)))
            return fail(Kind::Invalid, Problem::ShortSections);
        const uint64_t bytes = U32(section + 16), offset = U32(section + 20);
        // UPX-packed NirSoft executables can declare SizeOfHeaders=0x1000
        // while raw section data starts at 0x400. SizeOfHeaders is NOT a
        // reliable lower bound for raw data. Protect the bytes actually occupied
        // by DOS/PE/optional/section headers, and still reject out-of-file data.
        if (bytes && (offset < sectionEnd || offset > length || bytes > length - offset))
            return fail(Kind::Invalid, Problem::SectionRange);
    }
    return {(flags & 0x2000) ? Kind::Dll : Kind::Exe, Problem::None};
}
inline Kind Detect(const Read& raw, uint64_t length) { return Inspect(raw, length).kind; }
}
