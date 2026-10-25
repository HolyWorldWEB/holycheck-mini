#pragma once
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

// RFC 1951 raw DEFLATE decoder for ZIP. No runtime or third-party dependency.
// Bounds and output limits are supplied by the validated ZIP central directory.
namespace HolyDeflate {
using Read = std::function<bool(uint64_t, void*, size_t)>;
using Write = std::function<bool(const unsigned char*, size_t)>;

inline uint32_t Crc32(uint32_t crc, const unsigned char* data, size_t count) {
    // IEEE CRC-32, same polynomial/init/final XOR and streaming contract.
    // One immutable 1KiB lookup table, shared by all existing worker threads.
    static const auto table=[] {
        std::array<uint32_t,256> values{};
        for(unsigned i=0;i<values.size();++i) {
            uint32_t value=i;
            for(unsigned bit=0;bit<8;++bit)value=(value>>1)^((value&1)?0xedb88320u:0u);
            values[i]=value;
        }
        return values;
    }();
    crc = ~crc;
    for(size_t i=0;i<count;++i)crc=(crc>>8)^table[(crc^data[i])&0xffu];
    return ~crc;
}

class Bits {
    const Read& source_;
    uint64_t start_;
    uint32_t length_;
    uint32_t consumed_ = 0;
    std::array<unsigned char, 65536> input_{};
    size_t pos_ = 0, available_ = 0;
    unsigned byte_ = 0, left_ = 0;
public:
    Bits(const Read& source, uint64_t start, uint32_t length)
        : source_(source), start_(start), length_(length) {}
    bool Get(unsigned n, unsigned& result) {
        result = 0;
        if (n > 16) return false;
        unsigned shift=0;
        while(n) {
            if (!left_) {
                if (pos_ == available_) {
                    if (consumed_ == length_) return false;
                    const size_t count = static_cast<size_t>(
                        std::min<uint32_t>(static_cast<uint32_t>(input_.size()), length_ - consumed_));
                    if (!source_(start_ + consumed_, input_.data(), count)) return false;
                    consumed_ += static_cast<uint32_t>(count);
                    available_ = count; pos_ = 0;
                }
                byte_ = input_[pos_++]; left_ = 8;
            }
            // Consume at most one byte's remaining bits per iteration. No
            // speculative read-ahead: EOF, Align and strict End stay unchanged.
            const unsigned take=std::min(n,left_);
            result|=(byte_&((1u<<take)-1u))<<shift;
            byte_>>=take;left_-=take;shift+=take;n-=take;
        }
        return true;
    }
    void Align() { left_ = 0; }
    bool End() const { return pos_ == available_ && consumed_ == length_; }
};

struct Huffman {
    std::array<unsigned, 16> count{};
    std::vector<uint16_t> table;
    unsigned maximum_ = 0;
    // Canonical codes indexed by (length, reversed code); bounded by actual maximum code length.
    bool Build(const std::vector<unsigned>& lengths, unsigned maximum = 15) {
        table.clear(); maximum_ = 0;
        if (maximum == 0 || maximum > 15) return false;
        count.fill(0);
        unsigned usedMaximum=0;
        for (unsigned value : lengths) {
            if (value > maximum) return false;
            if (value) {++count[value];usedMaximum=std::max(usedMaximum,value);}
        }
        int open = 1;
        for (unsigned i = 1; i <= maximum; ++i) {
            open = 2 * open - static_cast<int>(count[i]);
            if (open < 0) return false;
        }
        if (count[1] + count[2] + count[3] + count[4] + count[5] +
            count[6] + count[7] + count[8] + count[9] + count[10] +
            count[11] + count[12] + count[13] + count[14] + count[15] == 0) return false;
        // Incomplete trees are legal only with one one-bit symbol.
        if (open && !(count[1] == 1 && [&] {
            for (unsigned i = 2; i <= maximum; ++i) if (count[i]) return false;
            return true;
        }())) return false;
        table.assign(1u << (usedMaximum + 1), 0);
        maximum_ = usedMaximum;
        std::array<unsigned, 16> next{};
        unsigned code = 0;
        for (unsigned i = 1; i <= maximum; ++i) {
            code = (code + count[i - 1]) << 1;
            next[i] = code;
        }
        for (size_t symbol = 0; symbol < lengths.size(); ++symbol) {
            const unsigned n = lengths[symbol];
            if (!n) continue;
            unsigned word = next[n]++, reversed = 0;
            for (unsigned i = 0; i < n; ++i) { reversed = (reversed << 1) | (word & 1u); word >>= 1; }
            table[(1u << n) | reversed] = static_cast<uint16_t>(symbol + 1);
        }
        return true;
    }
    bool Decode(Bits& bits, unsigned& symbol) const {
        unsigned reversed = 0;
        for (unsigned n = 1; n <= maximum_; ++n) {
            unsigned bit = 0;
            if (!bits.Get(1, bit)) return false;
            reversed |= bit << (n - 1);
            const size_t index = (1u << n) | reversed;
            if (index >= table.size()) return false;
            const uint16_t match = table[index];
            if (match) { symbol = match - 1; return true; }
        }
        return false;
    }
};

inline bool Expand(const Read& read, uint64_t start, uint32_t compressed,
                   uint32_t expected, uint32_t checksum, const Write& write) {
    Bits bits(read, start, compressed);
    std::array<unsigned char, 32768> window{};
    std::array<unsigned char, 65536> output{};
    size_t buffered = 0;
    uint64_t produced = 0;
    uint32_t crc = 0;
    auto flush = [&]() {
        if (!buffered) return true;
        crc = Crc32(crc, output.data(), buffered);
        const bool ok = write(output.data(), buffered);
        buffered = 0;
        return ok;
    };
    auto emit = [&](unsigned char value) {
        if (produced >= expected) return false;
        window[static_cast<size_t>(produced % window.size())] = value;
        output[buffered++] = value; ++produced;
        return buffered != output.size() || flush();
    };
    bool final = false;
    while (!final) {
        unsigned last = 0, type = 0;
        if (!bits.Get(1, last) || !bits.Get(2, type) || type == 3) return false;
        final = last != 0;
        if (type == 0) {
            bits.Align();
            unsigned length = 0, inverse = 0;
            if (!bits.Get(16, length) || !bits.Get(16, inverse) ||
                (length ^ inverse) != 0xffffu) return false;
            for (unsigned i = 0; i < length; ++i) {
                unsigned byte = 0;
                if (!bits.Get(8, byte) || !emit(static_cast<unsigned char>(byte))) return false;
            }
            continue;
        }
        Huffman literal, distance;
        const Huffman* literalTree=&literal;
        const Huffman* distanceTree=&distance;
        if (type == 1) {
            // Fixed codes are identical in every block. C++17 local-static
            // initialization is thread safe; trees are read-only afterwards.
            struct FixedTrees {
                Huffman literal,distance;
                bool valid=false;
                FixedTrees() {
                    std::vector<unsigned> lengths(288),distances(32,5);
                    for(unsigned i=0;i<288;++i)
                        lengths[i]=i<144?8:i<256?9:i<280?7:8;
                    valid=literal.Build(lengths)&&distance.Build(distances);
                }
            };
            static const FixedTrees fixed;
            if(!fixed.valid)return false;
            literalTree=&fixed.literal;distanceTree=&fixed.distance;
        } else {
            unsigned l = 0, d = 0, c = 0;
            if (!bits.Get(5, l) || !bits.Get(5, d) || !bits.Get(4, c)) return false;
            l += 257; d += 1; c += 4;
            if (l > 286 || d > 32) return false;
            static constexpr unsigned order[19] = {
                16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15
            };
            std::vector<unsigned> codeLengths(19, 0);
            for (unsigned i = 0; i < c; ++i)
                if (!bits.Get(3, codeLengths[order[i]])) return false;
            Huffman codes;
            if (!codes.Build(codeLengths, 7)) return false;
            std::vector<unsigned> lengths;
            lengths.reserve(l + d);
            while (lengths.size() < l + d) {
                unsigned symbol = 0, count = 0, value = 0;
                if (!codes.Decode(bits, symbol)) return false;
                if (symbol <= 15) { lengths.push_back(symbol); continue; }
                if (symbol == 16) {
                    if (lengths.empty() || !bits.Get(2, count)) return false;
                    count += 3; value = lengths.back();
                } else if (symbol == 17) {
                    if (!bits.Get(3, count)) return false;
                    count += 3;
                } else if (symbol == 18) {
                    if (!bits.Get(7, count)) return false;
                    count += 11;
                } else return false;
                if (count > l + d - lengths.size()) return false;
                lengths.insert(lengths.end(), count, value);
            }
            if (lengths[256] == 0) return false;
            std::vector<unsigned> lit(lengths.begin(), lengths.begin() + l);
            std::vector<unsigned> dist(lengths.begin() + l, lengths.end());
            // A literal-only block may have no distance tree.
            bool hasDistance = false;
            for (unsigned value : dist) hasDistance = hasDistance || value != 0;
            if (!literal.Build(lit) || (hasDistance && !distance.Build(dist))) return false;
        }
        static constexpr unsigned baseLength[29] = {
            3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
        };
        static constexpr unsigned lengthBits[29] = {
            0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
        };
        static constexpr unsigned baseDistance[30] = {
            1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
        };
        static constexpr unsigned distanceBits[30] = {
            0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
        };
        for (;;) {
            unsigned symbol = 0;
            if (!literalTree->Decode(bits, symbol)) return false;
            if (symbol < 256) {
                if (!emit(static_cast<unsigned char>(symbol))) return false;
                continue;
            }
            if (symbol == 256) break;
            if (symbol < 257 || symbol > 285 || distanceTree->table.empty()) return false;
            const unsigned li = symbol - 257;
            unsigned extra = 0;
            if (!bits.Get(lengthBits[li], extra)) return false;
            const unsigned run = baseLength[li] + extra;
            unsigned distSymbol = 0;
            if (!distanceTree->Decode(bits, distSymbol) || distSymbol >= 30 ||
                !bits.Get(distanceBits[distSymbol], extra)) return false;
            const unsigned back = baseDistance[distSymbol] + extra;
            if (back > produced || back > window.size() || run > expected - produced) return false;
            for (unsigned i = 0; i < run; ++i)
                if (!emit(window[static_cast<size_t>((produced - back) % window.size())])) return false;
        }
    }
    return bits.End() && produced == expected && flush() && crc == checksum;
}
} // namespace HolyDeflate
