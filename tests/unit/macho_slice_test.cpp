#include "macho_slice.h"
#include "code_signature.h"
#include "utility.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <vector>

namespace {

    std::uint32_t AlignToEight(std::uint32_t value) {
        return (value + 7U) & ~7U;
    }

    std::uint32_t Encode(std::uint32_t value, bool bigEndian) {
        return bigEndian ? Utility::Swap(value) : value;
    }

    std::uint32_t Decode(std::uint32_t value, bool bigEndian) {
        return Encode(value, bigEndian);
    }

    std::uint32_t AppendDylibCommand(std::vector<std::uint8_t>& image, std::uint32_t offset, const std::string& path,
                                     bool bigEndian) {
        const std::uint32_t commandSize =
            AlignToEight(static_cast<std::uint32_t>(sizeof(dylib_command) + path.size() + 1U));
        image.resize(static_cast<std::size_t>(offset) + commandSize, 0);

        auto* command = reinterpret_cast<dylib_command*>(image.data() + offset);
        command->cmd = Encode(LC_LOAD_DYLIB, bigEndian);
        command->cmdsize = Encode(commandSize, bigEndian);
        command->dylib.name.offset = Encode(static_cast<std::uint32_t>(sizeof(dylib_command)), bigEndian);
        command->dylib.timestamp = Encode(2U, bigEndian);
        std::memcpy(image.data() + offset + sizeof(dylib_command), path.c_str(), path.size() + 1U);
        return commandSize;
    }

    bool RunRemovalCase(bool bigEndian) {
        constexpr const char* kRemovePath = "@rpath/libRemove.dylib";
        constexpr const char* kKeepPath = "@rpath/libKeep.dylib";

        std::vector<std::uint8_t> image(sizeof(mach_header_64), 0);
        const std::uint32_t firstCommandOffset = static_cast<std::uint32_t>(image.size());
        const std::uint32_t removedCommandSize = AppendDylibCommand(image, firstCommandOffset, kRemovePath, bigEndian);
        const std::uint32_t keptCommandSize =
            AppendDylibCommand(image, firstCommandOffset + removedCommandSize, kKeepPath, bigEndian);
        const std::uint32_t originalCommandBytes = removedCommandSize + keptCommandSize;

        auto* header = reinterpret_cast<mach_header_64*>(image.data());
        header->magic = bigEndian ? MH_CIGAM_64 : MH_MAGIC_64;
        header->cputype = static_cast<cpu_type_t>(Encode(CPU_TYPE_ARM64, bigEndian));
        header->cpusubtype = static_cast<cpu_subtype_t>(Encode(CPU_SUBTYPE_ARM64_ALL, bigEndian));
        header->filetype = Encode(MH_EXECUTE, bigEndian);
        header->ncmds = Encode(2U, bigEndian);
        header->sizeofcmds = Encode(originalCommandBytes, bigEndian);

        MachOSlice slice;
        if (!slice.Init(image.data(), static_cast<std::uint32_t>(image.size()))) {
            std::cerr << "failed to initialize " << (bigEndian ? "big" : "little") << "-endian test image\n";
            return false;
        }

        if (!slice.RemoveDylibs(std::set<std::string>{kRemovePath}))
            return false;

        header = reinterpret_cast<mach_header_64*>(image.data());
        if (Decode(header->ncmds, bigEndian) != 1U || Decode(header->sizeofcmds, bigEndian) != keptCommandSize) {
            std::cerr << "load-command metadata was not rebuilt correctly\n";
            return false;
        }

        const auto* keptCommand = reinterpret_cast<const dylib_command*>(image.data() + sizeof(mach_header_64));
        const std::uint32_t nameOffset = Decode(keptCommand->dylib.name.offset, bigEndian);
        const char* keptPath = reinterpret_cast<const char*>(image.data() + sizeof(mach_header_64) + nameOffset);
        if (Decode(keptCommand->cmd, bigEndian) != LC_LOAD_DYLIB ||
            Decode(keptCommand->cmdsize, bigEndian) != keptCommandSize || std::string(keptPath) != kKeepPath) {
            std::cerr << "the retained dylib command was corrupted\n";
            return false;
        }

        const auto clearedBegin = image.begin() + sizeof(mach_header_64) + keptCommandSize;
        const auto clearedEnd = image.begin() + sizeof(mach_header_64) + originalCommandBytes;
        if (!std::all_of(clearedBegin, clearedEnd, [](std::uint8_t byte) { return byte == 0; })) {
            std::cerr << "removed command bytes were not cleared\n";
            return false;
        }

        MachOSlice reparsed;
        if (!reparsed.Init(image.data(), static_cast<std::uint32_t>(image.size()))) {
            std::cerr << "rebuilt Mach-O command table could not be reparsed\n";
            return false;
        }

        return true;
    }

    bool RunDerIntegerCases() {
        struct Case {
            std::int64_t value;
            std::vector<std::uint8_t> expected;
        };
        const std::vector<Case> cases = {
            {0, {0x02, 0x01, 0x00}},  {127, {0x02, 0x01, 0x7f}},        {128, {0x02, 0x02, 0x00, 0x80}},
            {-1, {0x02, 0x01, 0xff}}, {-129, {0x02, 0x02, 0xff, 0x7f}},
        };
        for (const Case& test : cases) {
            const std::string encoded = CodeSignature::_DER(jvalue(test.value));
            if (encoded.size() != test.expected.size() ||
                !std::equal(
                    encoded.begin(), encoded.end(), test.expected.begin(),
                    [](char actual, std::uint8_t expected) { return static_cast<std::uint8_t>(actual) == expected; })) {
                std::cerr << "non-canonical DER INTEGER for " << test.value << "\n";
                return false;
            }
        }
        std::string unsupported;
        if (CodeSignature::_DERChecked(jvalue(1.5), unsupported) ||
            CodeSignature::SlotBuildDerEntitlements("not a plist", unsupported)) {
            std::cerr << "unsupported or malformed DER entitlements were accepted\n";
            return false;
        }
        return true;
    }

    bool RunMalformedSuperBlobCases() {
        std::vector<std::uint8_t> blob(sizeof(CS_SuperBlob), 0);
        auto* header = reinterpret_cast<CS_SuperBlob*>(blob.data());
        header->magic = Utility::Swap(static_cast<std::uint32_t>(CSMAGIC_EMBEDDED_SIGNATURE));
        header->length = Utility::Swap(static_cast<std::uint32_t>(blob.size()));
        header->count = Utility::Swap(std::numeric_limits<std::uint32_t>::max());
        if (CodeSignature::ParseCodeSignature(blob.data(), static_cast<std::uint32_t>(blob.size()))) {
            std::cerr << "accepted overflowing superblob index count\n";
            return false;
        }
        header->count = 0;
        header->length = Utility::Swap(static_cast<std::uint32_t>(blob.size() + 1));
        if (CodeSignature::ParseCodeSignature(blob.data(), static_cast<std::uint32_t>(blob.size()))) {
            std::cerr << "accepted superblob length beyond LC_CODE_SIGNATURE capacity\n";
            return false;
        }
        return true;
    }

} // namespace

int main() {
    return RunRemovalCase(false) && RunRemovalCase(true) && RunDerIntegerCases() && RunMalformedSuperBlobCases() ? 0
                                                                                                                 : 1;
}
