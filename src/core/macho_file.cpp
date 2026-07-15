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
#include <random>
#ifdef __APPLE__
#include <copyfile.h>
#elif defined(__linux__)
#include <sys/xattr.h>
#endif
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

    std::string RandomTemporaryPath(const std::string& filePath, const char* purpose) {
        std::random_device random;
        const std::uint64_t nonce = (static_cast<std::uint64_t>(random()) << 32) ^ random() ^ Utility::GetMicroSecond();
        return filePath + ".orchardseal-" + purpose + "-" + std::to_string(nonce) + ".tmp";
    }

    bool WriteExclusiveTemporary(const std::string& filePath, const char* purpose, const std::uint8_t* data,
                                 std::size_t size, std::string& outputPath) {
        if (data == nullptr && size != 0)
            return false;
        for (unsigned attempt = 0; attempt < 32; ++attempt) {
            outputPath = RandomTemporaryPath(filePath, purpose);
#ifdef _WIN32
            if (outputPath.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
                return false;
            const int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, outputPath.data(),
                                                       static_cast<int>(outputPath.size()), nullptr, 0);
            if (wideLength <= 0)
                return false;
            std::wstring widePath(static_cast<size_t>(wideLength), L'\0');
            if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, outputPath.data(),
                                    static_cast<int>(outputPath.size()), widePath.data(), wideLength) != wideLength)
                return false;
            HANDLE handle = CreateFileW(widePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (handle == INVALID_HANDLE_VALUE) {
                if (GetLastError() == ERROR_FILE_EXISTS || GetLastError() == ERROR_ALREADY_EXISTS)
                    continue;
                return false;
            }
            std::size_t written = 0;
            bool success = true;
            while (written < size) {
                const DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(size - written, 1U << 30));
                DWORD chunkWritten = 0;
                if (::WriteFile(handle, data + written, chunk, &chunkWritten, nullptr) == 0 || chunkWritten != chunk) {
                    success = false;
                    break;
                }
                written += chunkWritten;
            }
            success = success && FlushFileBuffers(handle) != 0;
            success = CloseHandle(handle) != 0 && success;
            if (!success)
                DeleteFileW(widePath.c_str());
            return success;
#else
            const int descriptor = open(outputPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            if (descriptor < 0) {
                if (errno == EEXIST)
                    continue;
                return false;
            }
            std::size_t written = 0;
            while (written < size) {
                const ssize_t result = write(descriptor, data + written, size - written);
                if (result < 0 && errno == EINTR)
                    continue;
                if (result <= 0)
                    break;
                written += static_cast<std::size_t>(result);
            }
            const bool contentWritten = written == size;
            const bool synchronized = contentWritten && fsync(descriptor) == 0;
            const bool closed = close(descriptor) == 0;
            const bool success = contentWritten && synchronized && closed;
            if (!success) {
                FileSystem::RemoveFile(outputPath.c_str());
            }
            return success;
#endif
        }
        return false;
    }

    bool CopyReplacementMetadata(const std::string& source, const std::string& destination) {
#ifdef __APPLE__
        return copyfile(source.c_str(), destination.c_str(), nullptr, COPYFILE_METADATA | COPYFILE_NOFOLLOW) == 0;
#elif !defined(_WIN32)
        struct stat metadata{};
        if (lstat(source.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            chmod(destination.c_str(), metadata.st_mode & 07777) != 0)
            return false;
        if (chown(destination.c_str(), metadata.st_uid, metadata.st_gid) != 0 && errno != EPERM)
            return false;
        const timespec times[] = {metadata.st_atim, metadata.st_mtim};
        if (utimensat(AT_FDCWD, destination.c_str(), times, AT_SYMLINK_NOFOLLOW) != 0)
            return false;
#ifdef __linux__
        const ssize_t namesLength = llistxattr(source.c_str(), nullptr, 0);
        if (namesLength < 0)
            return false;
        std::vector<char> names(static_cast<size_t>(namesLength));
        if (namesLength > 0 && llistxattr(source.c_str(), names.data(), names.size()) != namesLength)
            return false;
        for (size_t offset = 0; offset < names.size();) {
            const string name(names.data() + offset);
            offset += name.size() + 1;
            if (name.compare(0, 5, "user.") != 0)
                continue;
            const ssize_t valueLength = lgetxattr(source.c_str(), name.c_str(), nullptr, 0);
            if (valueLength < 0)
                return false;
            std::vector<uint8_t> value(static_cast<size_t>(valueLength));
            if (valueLength > 0 && lgetxattr(source.c_str(), name.c_str(), value.data(), value.size()) != valueLength)
                return false;
            if (lsetxattr(destination.c_str(), name.c_str(), value.data(), value.size(), 0) != 0)
                return false;
        }
#endif
        return true;
#else
        auto toWide = [](const string& input, std::wstring& output) {
            if (input.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
                return false;
            const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                                   static_cast<int>(input.size()), nullptr, 0);
            if (length <= 0)
                return false;
            output.assign(static_cast<size_t>(length), L'\0');
            return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
                                       output.data(), length) == length;
        };
        std::wstring sourcePath, destinationPath;
        if (!toWide(source, sourcePath) || !toWide(destination, destinationPath))
            return false;
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        if (!GetFileAttributesExW(sourcePath.c_str(), GetFileExInfoStandard, &attributes))
            return false;
        HANDLE destinationHandle = CreateFileW(destinationPath.c_str(), FILE_WRITE_ATTRIBUTES | WRITE_DAC, 0, nullptr,
                                               OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (destinationHandle == INVALID_HANDLE_VALUE)
            return false;
        bool success = SetFileTime(destinationHandle, &attributes.ftCreationTime, &attributes.ftLastAccessTime,
                                   &attributes.ftLastWriteTime) != 0;
        DWORD securityLength = 0;
        GetFileSecurityW(sourcePath.c_str(), DACL_SECURITY_INFORMATION, nullptr, 0, &securityLength);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || securityLength == 0)
            success = false;
        std::vector<uint8_t> security(securityLength);
        if (success && (!GetFileSecurityW(sourcePath.c_str(), DACL_SECURITY_INFORMATION, security.data(),
                                          securityLength, &securityLength) ||
                        !SetFileSecurityW(destinationPath.c_str(), DACL_SECURITY_INFORMATION,
                                          reinterpret_cast<PSECURITY_DESCRIPTOR>(security.data()))))
            success = false;
        success = CloseHandle(destinationHandle) != 0 && success;
        const DWORD safeAttributes = attributes.dwFileAttributes & ~FILE_ATTRIBUTE_REPARSE_POINT;
        return success && SetFileAttributesW(destinationPath.c_str(), safeAttributes) != 0;
#endif
    }

    bool AppendSecureFile(const std::string& path, const uint8_t* data, size_t size) {
#ifdef _WIN32
        if (path.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
            return false;
        const int wideLength =
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()), nullptr, 0);
        if (wideLength <= 0)
            return false;
        std::wstring widePath(static_cast<size_t>(wideLength), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()),
                                widePath.data(), wideLength) != wideLength)
            return false;
        HANDLE handle = CreateFileW(widePath.c_str(), FILE_APPEND_DATA, 0, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (handle == INVALID_HANDLE_VALUE || GetFileType(handle) != FILE_TYPE_DISK) {
            if (handle != INVALID_HANDLE_VALUE)
                CloseHandle(handle);
            return false;
        }
        size_t written = 0;
        bool success = true;
        while (written < size) {
            const DWORD chunk = static_cast<DWORD>(std::min<size_t>(size - written, 1U << 30));
            DWORD chunkWritten = 0;
            if (::WriteFile(handle, data + written, chunk, &chunkWritten, nullptr) == 0 || chunkWritten != chunk) {
                success = false;
                break;
            }
            written += chunkWritten;
        }
        success = success && FlushFileBuffers(handle) != 0;
        return CloseHandle(handle) != 0 && success;
#else
        const int descriptor = open(path.c_str(), O_WRONLY | O_APPEND | O_NOFOLLOW);
        if (descriptor < 0)
            return false;
        struct stat status{};
        bool success = fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode);
        size_t written = 0;
        while (success && written < size) {
            const ssize_t result = write(descriptor, data + written, size - written);
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0) {
                success = false;
                break;
            }
            written += static_cast<size_t>(result);
        }
        success = success && fsync(descriptor) == 0;
        return close(descriptor) == 0 && success;
#endif
    }

} // namespace

MachOFile::~MachOFile() {
    CloseFile();
    if (!pendingOriginalFile_.empty())
        FileSystem::RemoveFile(pendingOriginalFile_.c_str());
}

bool MachOFile::Init(const char* file) {
    filePath_ = file == nullptr ? std::string() : file;
    codeSignatureReallocated_ = false;
    if (!pendingOriginalFile_.empty())
        FileSystem::RemoveFile(pendingOriginalFile_.c_str());
    pendingOriginalFile_.clear();
    return OpenFile(file, false);
}

bool MachOFile::InitReadOnly(const char* file) {
    filePath_ = file == nullptr ? std::string() : file;
    codeSignatureReallocated_ = false;
    if (!pendingOriginalFile_.empty())
        FileSystem::RemoveFile(pendingOriginalFile_.c_str());
    pendingOriginalFile_.clear();
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

bool MachOFile::ReplaceAndReopen(std::string& temporaryFile) {
    if (temporaryFile.empty() || filePath_.empty() || !CloseFile()) {
        return false;
    }

    if (!CopyReplacementMetadata(filePath_, temporaryFile)) {
        Logger::ErrorV(">>> Could not preserve Mach-O file metadata: %s\n", std::strerror(errno));
        OpenFile(filePath_.c_str(), false);
        return false;
    }

    const std::string backupFile = RandomTemporaryPath(filePath_, "backup");
    if (!FileSystem::Rename(filePath_.c_str(), backupFile.c_str())) {
        Logger::ErrorV(">>> Could not preserve the original Mach-O file: %s\n", std::strerror(errno));
        OpenFile(filePath_.c_str(), false);
        return false;
    }

    if (!FileSystem::Rename(temporaryFile.c_str(), filePath_.c_str())) {
        const int replacementError = errno;
        if (FileSystem::Rename(backupFile.c_str(), filePath_.c_str())) {
            const bool reopened = OpenFile(filePath_.c_str(), false);
            Logger::ErrorV(">>> Could not replace the Mach-O file: %s; original %s.\n", std::strerror(replacementError),
                           reopened ? "restored" : "restored but could not be reopened");
        } else {
            const std::string failedReplacement = RandomTemporaryPath(filePath_, "failed-replacement");
            const std::string retainedTemporary = temporaryFile;
            const bool moved = FileSystem::Rename(temporaryFile.c_str(), failedReplacement.c_str());
            temporaryFile.clear();
            Logger::ErrorV(">>> Replacement and rollback both failed. Original backup retained at %s; replacement "
                           "retained at %s.\n",
                           backupFile.c_str(), moved ? failedReplacement.c_str() : retainedTemporary.c_str());
        }
        return false;
    }

    if (OpenFile(filePath_.c_str(), false)) {
        FileSystem::RemoveFile(backupFile.c_str());
        return true;
    }

    const std::string invalidReplacement = RandomTemporaryPath(filePath_, "invalid-replacement");
    if (!FileSystem::Rename(filePath_.c_str(), invalidReplacement.c_str())) {
        Logger::ErrorV(
            ">>> Replacement validation failed. Invalid replacement retained at %s; original backup retained at %s.\n",
            filePath_.c_str(), backupFile.c_str());
        return false;
    }
    if (!FileSystem::Rename(backupFile.c_str(), filePath_.c_str())) {
        Logger::ErrorV(">>> Replacement validation failed and rollback failed. Invalid replacement retained at %s; "
                       "original backup retained at %s.\n",
                       invalidReplacement.c_str(), backupFile.c_str());
        return false;
    }
    if (!OpenFile(filePath_.c_str(), false)) {
        Logger::ErrorV(
            ">>> Original Mach-O was restored at %s but could not be reopened; invalid replacement retained at %s.\n",
            filePath_.c_str(), invalidReplacement.c_str());
        return false;
    }
    FileSystem::RemoveFile(invalidReplacement.c_str());
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

    std::string temporaryFile;
    if (!WriteExclusiveTemporary(filePath_, "signing", mappedData_, mappedSize_, temporaryFile)) {
        RestorePendingOriginal();
        return false;
    }
    MachOFile candidate;
    const bool signedSuccessfully = candidate.Init(temporaryFile.c_str()) &&
                                    candidate.SignInPlace(signingAsset, force, std::move(bundleId), std::move(infoSha1),
                                                          std::move(infoSha256), codeResourcesData);
    candidate.Free();
    if (!signedSuccessfully) {
        FileSystem::RemoveFile(temporaryFile.c_str());
        RestorePendingOriginal();
        return false;
    }
    const bool replaced = ReplaceAndReopen(temporaryFile);
    FileSystem::RemoveFile(temporaryFile.c_str());
    if (!replaced) {
        RestorePendingOriginal();
        return false;
    }
    if (!pendingOriginalFile_.empty())
        FileSystem::RemoveFile(pendingOriginalFile_.c_str());
    pendingOriginalFile_.clear();
    return CloseFile();
}

bool MachOFile::SignInPlace(SigningAsset* signingAsset, bool force, std::string bundleId, std::string infoSha1,
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
                    return SignInPlace(signingAsset, force, bundleId, infoSha1, infoSha256, codeResourcesData);
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
        const std::string sliceFile = RandomTemporaryPath(filePath_, ("slice-" + std::to_string(index)).c_str());
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

    std::string fatOutputFile;
    std::string headerData;
    headerData.append(reinterpret_cast<const char*>(&fatHeader), sizeof(fatHeader));
    headerData.append(reinterpret_cast<const char*>(architectures.data()), sizeof(fat_arch) * architectures.size());
    headerData.append(Utility::ByteAlign(headerSize, kFatSliceAlignment) - headerSize, 0);
    if (!WriteExclusiveTemporary(filePath_, "fat", reinterpret_cast<const std::uint8_t*>(headerData.data()),
                                 headerData.size(), fatOutputFile)) {
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
        assembled = AppendSecureFile(fatOutputFile, static_cast<const uint8_t*>(sliceData), mappedSliceSize) &&
                    AppendSecureFile(fatOutputFile, reinterpret_cast<const uint8_t*>(padding.data()), padding.size());
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

    if (!CaptureOriginalForRollback())
        return false;
    std::string temporaryFile;
    if (!WriteExclusiveTemporary(filePath_, "inject", mappedData_, mappedSize_, temporaryFile)) {
        RestorePendingOriginal();
        return false;
    }
    MachOFile candidate;
    const bool injected = candidate.Init(temporaryFile.c_str()) && candidate.InjectDylibInPlace(weakInject, dylibFile);
    candidate.Free();
    if (!injected) {
        FileSystem::RemoveFile(temporaryFile.c_str());
        RestorePendingOriginal();
        return false;
    }
    const bool replaced = ReplaceAndReopen(temporaryFile);
    FileSystem::RemoveFile(temporaryFile.c_str());
    if (!replaced)
        RestorePendingOriginal();
    return replaced;
}

bool MachOFile::InjectDylibInPlace(bool weakInject, const char* dylibFile) {
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

bool MachOFile::RemoveDylibs(const std::set<std::string>& dylibs) {
    if (readOnly_ || mappedData_ == nullptr || slices_.empty())
        return false;
    if (dylibs.empty())
        return true;
    if (!CaptureOriginalForRollback())
        return false;
    std::string temporaryFile;
    if (!WriteExclusiveTemporary(filePath_, "remove", mappedData_, mappedSize_, temporaryFile)) {
        RestorePendingOriginal();
        return false;
    }
    MachOFile candidate;
    const bool removed = candidate.Init(temporaryFile.c_str()) && candidate.RemoveDylibsInPlace(dylibs);
    candidate.Free();
    if (!removed) {
        FileSystem::RemoveFile(temporaryFile.c_str());
        RestorePendingOriginal();
        return false;
    }
    const bool replaced = ReplaceAndReopen(temporaryFile);
    FileSystem::RemoveFile(temporaryFile.c_str());
    if (!replaced)
        RestorePendingOriginal();
    return replaced;
}

bool MachOFile::RemoveDylibsInPlace(const std::set<std::string>& dylibs) {
    return std::all_of(slices_.begin(), slices_.end(), [&](const auto& slice) { return slice->RemoveDylibs(dylibs); });
}

bool MachOFile::RestorePendingOriginal() {
    if (pendingOriginalFile_.empty())
        return true;
    std::string rollbackFile = pendingOriginalFile_;
    const bool restored = ReplaceAndReopen(rollbackFile);
    if (restored) {
        pendingOriginalFile_.clear();
    } else {
        // ReplaceAndReopen retains and reports both artifacts on rollback failure.
        // Relinquish ownership so the destructor cannot erase recovery evidence.
        pendingOriginalFile_.clear();
    }
    return restored;
}

bool MachOFile::CaptureOriginalForRollback() {
    if (!pendingOriginalFile_.empty())
        return true;
    return WriteExclusiveTemporary(filePath_, "original", mappedData_, mappedSize_, pendingOriginalFile_);
}
