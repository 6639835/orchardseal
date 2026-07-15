#pragma once

#include <cstdint>
#include <set>
#include <string>

#include "mach-o.h"
#include "signing_asset.h"

struct MachOSliceInfo {
    std::string architecture;
    std::string fileType;
    std::uint32_t sizeBytes = 0;
    bool is64Bit = false;
    bool bigEndian = false;
    bool encrypted = false;
    bool signaturePresent = false;
    bool executable = false;
};

class MachOSlice final {
  public:
    MachOSlice() = default;

    [[nodiscard]] bool Init(std::uint8_t* base, std::uint32_t length);

    [[nodiscard]] bool Sign(SigningAsset* signingAsset, bool force, const std::string& bundleId,
                            const std::string& infoSha1, const std::string& infoSha256,
                            const std::string& codeResourcesData);

    void PrintInfo();
    [[nodiscard]] bool IsExecute() const;
    [[nodiscard]] bool IsSigned() const;
    [[nodiscard]] MachOSliceInfo GetInfo() const;
    [[nodiscard]] bool InjectDylib(bool weakInject, const char* dylibFile);
    [[nodiscard]] bool RemoveDylibs(const std::set<std::string>& dylibs);
    [[nodiscard]] std::uint32_t ReallocCodeSignSpace(const std::string& newFile);

    [[nodiscard]] const std::string& InfoPlist() const noexcept {
        return infoPlist_;
    }
    [[nodiscard]] bool HasEnoughCodeSignatureSpace() const noexcept {
        return hasEnoughSpace_;
    }
    [[nodiscard]] std::uint8_t* SignatureData() noexcept {
        return signatureBase_;
    }
    [[nodiscard]] const std::uint8_t* SignatureData() const noexcept {
        return signatureBase_;
    }
    [[nodiscard]] std::uint32_t SignatureSize() const noexcept {
        return signatureLength_;
    }

  private:
    [[nodiscard]] std::uint32_t ByteOrder(std::uint32_t value) const;
    [[nodiscard]] std::uint64_t ByteOrder64(std::uint64_t value) const;
    [[nodiscard]] const char* GetFileType(std::uint32_t fileType) const;
    [[nodiscard]] const char* GetArchitecture(int cpuType, int cpuSubType) const;
    [[nodiscard]] bool BuildCodeSignature(SigningAsset* signingAsset, bool force, const std::string& bundleId,
                                          const std::string& infoSha1, const std::string& infoSha256,
                                          const std::string& codeResourcesSha1, const std::string& codeResourcesSha256,
                                          std::string& output);

    std::uint8_t* base_ = nullptr;
    std::uint32_t length_ = 0;
    std::uint32_t codeLength_ = 0;
    std::uint8_t* signatureBase_ = nullptr;
    std::uint32_t signatureLength_ = 0;
    std::uint32_t signatureCapacity_ = 0;
    std::string infoPlist_;
    bool encrypted_ = false;
    bool is64Bit_ = false;
    bool bigEndian_ = false;
    bool hasEnoughSpace_ = true;
    std::uint8_t* codeSignatureSegment_ = nullptr;
    std::uint8_t* linkEditSegment_ = nullptr;
    std::uint32_t loadCommandsFreeSpace_ = 0;
    std::uint32_t fileType_ = 0;
    mach_header* header_ = nullptr;
    std::uint32_t headerSize_ = 0;
    std::uint64_t execSegmentLimit_ = 0;
};
