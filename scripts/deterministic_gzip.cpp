#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

namespace {

constexpr std::size_t kMaximumStoredBlockSize = 65535;

std::uint32_t UpdateCrc32(std::uint32_t crc, const unsigned char* data, std::size_t size) {
    for (std::size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for (unsigned int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1U) ^ (0xedb88320U & (0U - (crc & 1U)));
        }
    }
    return crc;
}

void WriteLittleEndian16(std::ostream& output, std::uint16_t value) {
    output.put(static_cast<char>(value & 0xffU));
    output.put(static_cast<char>((value >> 8U) & 0xffU));
}

void WriteLittleEndian32(std::ostream& output, std::uint32_t value) {
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        output.put(static_cast<char>((value >> shift) & 0xffU));
    }
}

bool Compress(const std::string& inputPath, const std::string& outputPath) {
    std::ifstream input(inputPath, std::ios::binary);
    std::ofstream output(outputPath, std::ios::binary | std::ios::trunc);
    if (!input || !output) {
        return false;
    }

    // RFC 1952 header: gzip, DEFLATE, no optional fields, zero timestamp,
    // no compressor-specific flags, and an unknown operating system.
    constexpr std::array<unsigned char, 10> header = {0x1f, 0x8b, 0x08, 0x00, 0x00,
                                                       0x00, 0x00, 0x00, 0x00, 0xff};
    output.write(reinterpret_cast<const char*>(header.data()), static_cast<std::streamsize>(header.size()));

    std::array<unsigned char, kMaximumStoredBlockSize> current{};
    std::array<unsigned char, kMaximumStoredBlockSize> next{};
    input.read(reinterpret_cast<char*>(current.data()), static_cast<std::streamsize>(current.size()));
    std::streamsize currentSize = input.gcount();
    if (input.bad()) {
        return false;
    }

    std::uint32_t crc = 0xffffffffU;
    std::uint32_t inputSize = 0;
    do {
        input.read(reinterpret_cast<char*>(next.data()), static_cast<std::streamsize>(next.size()));
        const std::streamsize nextSize = input.gcount();
        if (input.bad()) {
            return false;
        }

        const bool finalBlock = nextSize == 0;
        output.put(finalBlock ? '\x01' : '\x00');
        const auto blockSize = static_cast<std::uint16_t>(currentSize);
        WriteLittleEndian16(output, blockSize);
        WriteLittleEndian16(output, static_cast<std::uint16_t>(~blockSize));
        output.write(reinterpret_cast<const char*>(current.data()), currentSize);

        crc = UpdateCrc32(crc, current.data(), static_cast<std::size_t>(currentSize));
        inputSize += static_cast<std::uint32_t>(currentSize);
        current.swap(next);
        currentSize = nextSize;
    } while (currentSize != 0);

    WriteLittleEndian32(output, ~crc);
    WriteLittleEndian32(output, inputSize);
    output.close();
    return output.good();
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "usage: deterministic_gzip INPUT OUTPUT\n";
        return 2;
    }
    if (Compress(argv[1], argv[2])) {
        return 0;
    }
    std::remove(argv[2]);
    std::cerr << "deterministic_gzip: failed to create " << argv[2] << '\n';
    return 1;
}
