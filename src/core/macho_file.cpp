#include "macho_file.h"

#include "code_signature.h"
#include "common.h"
#include "json.h"
#include "mach-o.h"
#include "signing_asset.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

    constexpr std::uint32_t kFatSliceAlignment = 16U * 1024U;
    constexpr std::uint32_t kFatSliceAlignmentExponent = 14U;

    void RemoveFiles(const std::vector<std::string>& paths) {
        for (const std::string& path : paths) {
            FileSystem::RemoveFile(path.c_str());
        }
    }

} // namespace

MachOFile::~MachOFile() {
    CloseFile();
}

bool MachOFile::Init(const char* file) {
    filePath_ = file == nullptr ? std::string() : file;
    codeSignatureReallocated_ = false;
    return OpenFile(file, false);
}

bool MachOFile::InitReadOnly(const char* file) {
    filePath_ = file == nullptr ? std::string() : file;
    codeSignatureReallocated_ = false;
    return OpenFile(file, true);
}

bool MachOFile::InitV(const char* path, ...) {
    FORMAT_V(path, file);
    return Init(file);
}

bool MachOFile::Free() {
    return CloseFile();
}

bool MachOFile::NewSlice(std::uint8_t* base, std::uint32_t length) {
    auto slice = std::make_unique<MachOSlice>();
    if (!slice->Init(base, length)) {
        return false;
    }
    slices_.push_back(std::move(slice));
    return true;
}

bool MachOFile::OpenFile(const char* path, bool readOnly) {
    CloseFile();
    if (path == nullptr || *path == '\0') {
        return false;
    }

    readOnly_ = readOnly;
    mappedData_ = static_cast<std::uint8_t*>(FileSystem::MapFile(path, 0, 0, &mappedSize_, readOnly));
    if (mappedData_ == nullptr || mappedSize_ < sizeof(std::uint32_t)) {
        CloseFile();
        return false;
    }

    std::uint32_t magic = 0;
    std::memcpy(&magic, mappedData_, sizeof(magic));
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        if (mappedSize_ < sizeof(fat_header)) {
            Logger::Error(">>> Invalid fat Mach-O header!\n");
            CloseFile();
            return false;
        }

        const auto* fatHeader = reinterpret_cast<const fat_header*>(mappedData_);
        const std::uint32_t architectureCount = magic == FAT_MAGIC ? fatHeader->nfat_arch : LE(fatHeader->nfat_arch);
        const std::size_t maximumArchitectureCount = (mappedSize_ - sizeof(fat_header)) / sizeof(fat_arch);
        if (architectureCount == 0 || architectureCount > maximumArchitectureCount) {
            Logger::Error(">>> Invalid fat Mach-O architecture table!\n");
            CloseFile();
            return false;
        }

        for (std::uint32_t index = 0; index < architectureCount; ++index) {
            const auto* architecture = reinterpret_cast<const fat_arch*>(
                mappedData_ + sizeof(fat_header) + sizeof(fat_arch) * static_cast<std::size_t>(index));
            const std::uint32_t offset = magic == FAT_MAGIC ? architecture->offset : LE(architecture->offset);
            const std::uint32_t length = magic == FAT_MAGIC ? architecture->size : LE(architecture->size);
            if (length == 0 || static_cast<std::uint64_t>(offset) + length > mappedSize_ ||
                !NewSlice(mappedData_ + offset, length)) {
                Logger::Error(">>> Invalid architecture bounds in fat Mach-O file!\n");
                CloseFile();
                return false;
            }
        }
    } else if (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        if (mappedSize_ > std::numeric_limits<std::uint32_t>::max() ||
            !NewSlice(mappedData_, static_cast<std::uint32_t>(mappedSize_))) {
            Logger::Error(">>> Invalid Mach-O file!\n");
            CloseFile();
            return false;
        }
    } else {
        Logger::ErrorV(">>> Invalid Mach-O file (magic: 0x%08x)!\n", magic);
        CloseFile();
        return false;
    }

    return !slices_.empty();
}

bool MachOFile::CloseFile() {
    slices_.clear();
    if (mappedData_ == nullptr || mappedSize_ == 0) {
        mappedData_ = nullptr;
        mappedSize_ = 0;
        readOnly_ = false;
        return true;
    }

    const bool unmapped = FileSystem::UnmapFile(mappedData_, mappedSize_);
    if (!unmapped) {
        Logger::ErrorV(">>> Failed to unmap Mach-O file: %p, %zu, %s\n", mappedData_, mappedSize_,
                       std::strerror(errno));
    }
    mappedData_ = nullptr;
    mappedSize_ = 0;
    readOnly_ = false;
    return unmapped;
}

bool MachOFile::ReplaceAndReopen(const std::string& temporaryFile) {
    if (temporaryFile.empty() || filePath_.empty() || !CloseFile()) {
        return false;
    }

    const std::string backupFile = filePath_ + ".orchardseal-backup.tmp";
    FileSystem::RemoveFile(backupFile.c_str());
    if (std::rename(filePath_.c_str(), backupFile.c_str()) != 0) {
        Logger::ErrorV(">>> Could not preserve the original Mach-O file: %s\n", std::strerror(errno));
        return false;
    }

    if (std::rename(temporaryFile.c_str(), filePath_.c_str()) != 0) {
        const int replacementError = errno;
        std::rename(backupFile.c_str(), filePath_.c_str());
        Logger::ErrorV(">>> Could not replace the Mach-O file: %s\n", std::strerror(replacementError));
        return false;
    }

    if (OpenFile(filePath_.c_str(), false)) {
        FileSystem::RemoveFile(backupFile.c_str());
        return true;
    }

    FileSystem::RemoveFile(filePath_.c_str());
    if (std::rename(backupFile.c_str(), filePath_.c_str()) == 0) {
        OpenFile(filePath_.c_str(), false);
    }
    Logger::Error(">>> Replacement Mach-O validation failed; the original file was restored.\n");
    return false;
}

void MachOFile::PrintInfo() {
    for (const auto& slice : slices_) {
        slice->PrintInfo();
    }
}

bool MachOFile::CheckSignature() const {
    return !slices_.empty() &&
           std::all_of(slices_.cbegin(), slices_.cend(), [](const auto& slice) { return slice->IsSigned(); });
}

std::vector<MachOSliceInfo> MachOFile::GetArchitectureInfo() const {
    std::vector<MachOSliceInfo> result;
    result.reserve(slices_.size());
    for (const auto& slice : slices_) {
        result.push_back(slice->GetInfo());
    }
    return result;
}

bool MachOFile::Sign(SigningAsset* signingAsset, bool force, std::string bundleId, std::string infoSha1,
                     std::string infoSha256, const std::string& codeResourcesData) {
    if (mappedData_ == nullptr || slices_.empty() || readOnly_) {
        return false;
    }

    for (const auto& slice : slices_) {
        if (bundleId.empty()) {
            jvalue info;
            info.read_plist(slice->InfoPlist());
            bundleId = info["CFBundleIdentifier"].as_cstr();
            if (bundleId.empty()) {
                bundleId = Utility::GetBaseName(filePath_.c_str());
            }
        }

        if (infoSha1.empty() || infoSha256.empty()) {
            if (slice->InfoPlist().empty()) {
                infoSha1.append(20, 0);
                infoSha256.append(32, 0);
            } else {
                Hash::SHA(slice->InfoPlist(), infoSha1, infoSha256);
            }
        }

        if (!slice->Sign(signingAsset, force, bundleId, infoSha1, infoSha256, codeResourcesData)) {
            if (!slice->HasEnoughCodeSignatureSpace() && !codeSignatureReallocated_) {
                codeSignatureReallocated_ = true;
                if (ReallocateCodeSignatureSpace()) {
                    return Sign(signingAsset, force, bundleId, infoSha1, infoSha256, codeResourcesData);
                }
            }
            return false;
        }
    }

    return CloseFile();
}

bool MachOFile::ReallocateCodeSignatureSpace() {
    if (readOnly_ || mappedData_ == nullptr || slices_.empty()) {
        return false;
    }

    Logger::Warn(">>> Reallocating code-signature space...\n");

    std::vector<std::uint32_t> sliceSizes;
    std::vector<std::string> sliceFiles;
    sliceSizes.reserve(slices_.size());
    sliceFiles.reserve(slices_.size());

    for (std::size_t index = 0; index < slices_.size(); ++index) {
        const std::string sliceFile = filePath_ + ".orchardseal-slice-" + std::to_string(index) + ".tmp";
        FileSystem::RemoveFile(sliceFile.c_str());
        const std::uint32_t newLength = slices_[index]->ReallocCodeSignSpace(sliceFile);
        if (newLength == 0) {
            RemoveFiles(sliceFiles);
            FileSystem::RemoveFile(sliceFile.c_str());
            Logger::Error(">>> Code-signature space reallocation failed.\n");
            return false;
        }
        sliceFiles.push_back(sliceFile);
        sliceSizes.push_back(newLength);
    }

    if (slices_.size() == 1U) {
        const bool replaced = ReplaceAndReopen(sliceFiles.front());
        RemoveFiles(sliceFiles);
        return replaced;
    }

    const std::size_t architectureCount = slices_.size();
    fat_header fatHeader{};
    std::memcpy(&fatHeader, mappedData_, sizeof(fatHeader));
    const std::uint32_t rawArchitectureCount =
        fatHeader.magic == FAT_MAGIC ? fatHeader.nfat_arch : LE(fatHeader.nfat_arch);
    if (rawArchitectureCount != architectureCount) {
        RemoveFiles(sliceFiles);
        return false;
    }

    std::vector<fat_arch> architectures(architectureCount);
    std::memcpy(architectures.data(), mappedData_ + sizeof(fat_header), sizeof(fat_arch) * architectureCount);

    const std::uint32_t headerSize =
        static_cast<std::uint32_t>(sizeof(fat_header) + sizeof(fat_arch) * architectureCount);
    std::uint32_t offset = Utility::ByteAlign(headerSize, kFatSliceAlignment);
    for (std::size_t index = 0; index < architectures.size(); ++index) {
        fat_arch& architecture = architectures[index];
        const std::uint32_t sliceSize = sliceSizes[index];
        architecture.align = fatHeader.magic == FAT_MAGIC ? kFatSliceAlignmentExponent : BE(kFatSliceAlignmentExponent);
        architecture.offset = fatHeader.magic == FAT_MAGIC ? offset : BE(offset);
        architecture.size = fatHeader.magic == FAT_MAGIC ? sliceSize : BE(sliceSize);

        const std::uint64_t nextOffset = static_cast<std::uint64_t>(offset) + sliceSize;
        const std::uint64_t largestAlignableOffset =
            std::numeric_limits<std::uint32_t>::max() - (kFatSliceAlignment - 1U);
        if (nextOffset > largestAlignableOffset) {
            RemoveFiles(sliceFiles);
            return false;
        }
        offset = Utility::ByteAlign(static_cast<std::uint32_t>(nextOffset), kFatSliceAlignment);
    }

    const std::string fatOutputFile = filePath_ + ".orchardseal-fat.tmp";
    FileSystem::RemoveFile(fatOutputFile.c_str());
    std::string headerData;
    headerData.append(reinterpret_cast<const char*>(&fatHeader), sizeof(fatHeader));
    headerData.append(reinterpret_cast<const char*>(architectures.data()), sizeof(fat_arch) * architectures.size());
    headerData.append(Utility::ByteAlign(headerSize, kFatSliceAlignment) - headerSize, 0);
    if (!FileSystem::WriteFile(fatOutputFile.c_str(), headerData)) {
        RemoveFiles(sliceFiles);
        return false;
    }

    bool assembled = true;
    for (std::size_t index = 0; index < sliceFiles.size(); ++index) {
        std::size_t mappedSliceSize = 0;
        void* sliceData = FileSystem::MapFile(sliceFiles[index].c_str(), 0, 0, &mappedSliceSize, true);
        if (sliceData == nullptr || mappedSliceSize != sliceSizes[index]) {
            if (sliceData != nullptr) {
                FileSystem::UnmapFile(sliceData, mappedSliceSize);
            }
            assembled = false;
            break;
        }

        const std::size_t alignedSize = Utility::ByteAlign(sliceSizes[index], kFatSliceAlignment);
        const std::string padding(alignedSize - mappedSliceSize, '\0');
        assembled =
            FileSystem::AppendFile(fatOutputFile.c_str(), static_cast<const char*>(sliceData), mappedSliceSize) &&
            FileSystem::AppendFile(fatOutputFile.c_str(), padding);
        FileSystem::UnmapFile(sliceData, mappedSliceSize);
        if (!assembled) {
            break;
        }
    }

    RemoveFiles(sliceFiles);
    if (!assembled) {
        FileSystem::RemoveFile(fatOutputFile.c_str());
        return false;
    }

    const bool replaced = ReplaceAndReopen(fatOutputFile);
    FileSystem::RemoveFile(fatOutputFile.c_str());
    return replaced;
}

bool MachOFile::InjectDylib(bool weakInject, const char* dylibFile) {
    if (readOnly_ || mappedData_ == nullptr || slices_.empty()) {
        return false;
    }

    Logger::WarnV(">>> Injecting dylib: %s %s...\n", dylibFile, weakInject ? "(weak)" : "");
    for (const auto& slice : slices_) {
        if (!slice->InjectDylib(weakInject, dylibFile)) {
            Logger::Error(">>> Dylib injection failed.\n");
            return false;
        }
    }
    Logger::Warn(">>> Dylib injection succeeded.\n");
    return true;
}

void MachOFile::RemoveDylibs(const std::set<std::string>& dylibs) {
    if (readOnly_ || mappedData_ == nullptr) {
        return;
    }
    for (const auto& slice : slices_) {
        slice->RemoveDylibs(dylibs);
    }
}
