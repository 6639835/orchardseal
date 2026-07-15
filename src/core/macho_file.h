#pragma once

#include "macho_slice.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <vector>

class MachOFile {
  public:
    MachOFile() = default;
    ~MachOFile();

    MachOFile(const MachOFile&) = delete;
    MachOFile& operator=(const MachOFile&) = delete;
    MachOFile(MachOFile&&) = delete;
    MachOFile& operator=(MachOFile&&) = delete;

    bool Init(const char* file);
    bool InitReadOnly(const char* file);
    bool InitV(const char* path, ...);
    bool Free();
    void PrintInfo();
    [[nodiscard]] bool CheckSignature() const;
    [[nodiscard]] std::vector<MachOSliceInfo> GetArchitectureInfo() const;
    bool Sign(SigningAsset* signingAsset, bool force, std::string bundleId, std::string infoSha1,
              std::string infoSha256, const std::string& codeResourcesData);
    bool InjectDylib(bool weakInject, const char* dylibFile);
    [[nodiscard]] bool RemoveDylibs(const std::set<std::string>& dylibs);

  private:
    bool OpenFile(const char* path, bool readOnly);
    bool CloseFile();
    bool ReplaceAndReopen(std::string& temporaryFile);
    bool NewSlice(std::uint8_t* base, std::uint32_t length);
    bool ReallocateCodeSignatureSpace();
    bool SignInPlace(SigningAsset* signingAsset, bool force, std::string bundleId, std::string infoSha1,
                     std::string infoSha256, const std::string& codeResourcesData);
    bool InjectDylibInPlace(bool weakInject, const char* dylibFile);
    bool RemoveDylibsInPlace(const std::set<std::string>& dylibs);
    bool CaptureOriginalForRollback();
    bool RestorePendingOriginal();

    std::size_t mappedSize_ = 0;
    std::string filePath_;
    std::uint8_t* mappedData_ = nullptr;
    bool codeSignatureReallocated_ = false;
    bool readOnly_ = false;
    std::vector<std::unique_ptr<MachOSlice>> slices_;
    std::string pendingOriginalFile_;
};
