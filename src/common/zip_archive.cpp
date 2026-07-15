#include "zip_archive.h"

#include "common.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <random>
#include <set>
#include <string>
#include <vector>

#if defined(ORCHARDSEAL_SYSTEM_MINIZIP_NG)
#include <unzip.h>
#include <zip.h>
#elif defined(ORCHARDSEAL_SYSTEM_MINIZIP)
#include <minizip/unzip.h>
#include <minizip/zip.h>
#else
#include "unzip.h"
#include "zip.h"
#endif

#ifdef _WIN32
#include <io.h>
#include <iowin32.h>
#endif

namespace {

    constexpr std::uint64_t kMaximumEntryPathLength = 64U * 1024U;
    constexpr std::size_t kExtractionBufferSize = 512U * 1024U;
    constexpr std::uint64_t kMaximumEntryCount = 100000U;
    constexpr std::uint64_t kMaximumEntrySize = UINT64_C(4) * 1024U * 1024U * 1024U;
    constexpr std::uint64_t kMaximumTotalSize = UINT64_C(16) * 1024U * 1024U * 1024U;
    constexpr std::uint64_t kMaximumCompressionRatio = 1000U;

    namespace fs = std::filesystem;

#ifdef _WIN32
    bool Utf8ToWide(const std::string& input, std::wstring& output) {
        output.clear();
        if (input.empty()) {
            return false;
        }
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                              static_cast<int>(input.size()), nullptr, 0);
        if (count <= 0) {
            return false;
        }
        output.resize(static_cast<size_t>(count));
        return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
                                   output.data(), count) == count;
    }

    zipFile OpenZipForWriting(const std::string& path) {
        std::wstring widePath;
        if (!Utf8ToWide(path, widePath)) {
            return nullptr;
        }
        zlib_filefunc64_def functions{};
        fill_win32_filefunc64W(&functions);
        return zipOpen2_64(widePath.c_str(), APPEND_STATUS_CREATE, nullptr, &functions);
    }

    unzFile OpenZipForReading(const char* path) {
        std::wstring widePath;
        if (path == nullptr || !Utf8ToWide(path, widePath)) {
            return nullptr;
        }
        zlib_filefunc64_def functions{};
        fill_win32_filefunc64W(&functions);
        return unzOpen2_64(widePath.c_str(), &functions);
    }
#else
    zipFile OpenZipForWriting(const std::string& path) {
        return zipOpen64(path.c_str(), APPEND_STATUS_CREATE);
    }
    unzFile OpenZipForReading(const char* path) {
        return unzOpen64(path);
    }
#endif

    struct SourceStatus {
        bool regular = false;
        bool directory = false;
        std::uint64_t size = 0;
        time_t modificationTime = 0;
        unsigned int mode = 0;
#ifndef _WIN32
        dev_t device = 0;
        ino_t inode = 0;
#endif
    };

    bool GetSourceStatus(const std::string& path, SourceStatus& status) {
        status = SourceStatus{};
#ifdef _WIN32
        std::wstring widePath;
        if (!Utf8ToWide(path, widePath)) {
            return false;
        }
        const DWORD attributes = GetFileAttributesW(widePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
            return false;
        }
        struct _stat64 wideStatus{};
        if (_wstat64(widePath.c_str(), &wideStatus) != 0) {
            return false;
        }
        if (wideStatus.st_size < 0) {
            return false;
        }
        status.directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && (wideStatus.st_mode & _S_IFMT) == _S_IFDIR;
        status.regular = (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 && (wideStatus.st_mode & _S_IFMT) == _S_IFREG;
        status.size = static_cast<std::uint64_t>(wideStatus.st_size);
        status.modificationTime = wideStatus.st_mtime;
        status.mode = static_cast<unsigned int>(wideStatus.st_mode);
        return true;
#else
        struct stat nativeStatus{};
        if (lstat(path.c_str(), &nativeStatus) != 0 || S_ISLNK(nativeStatus.st_mode) || nativeStatus.st_size < 0) {
            return false;
        }
        status.regular = S_ISREG(nativeStatus.st_mode);
        status.directory = S_ISDIR(nativeStatus.st_mode);
        status.size = static_cast<std::uint64_t>(nativeStatus.st_size);
        status.modificationTime = nativeStatus.st_mtime;
        status.mode = static_cast<unsigned int>(nativeStatus.st_mode);
        status.device = nativeStatus.st_dev;
        status.inode = nativeStatus.st_ino;
        return true;
#endif
    }

    unsigned int SanitizedMode(unsigned int archivedMode, bool directory) {
        if (directory) {
            return 0755U;
        }
        return (archivedMode & 0111U) != 0 ? 0755U : 0644U;
    }

    bool IsPathWithin(const fs::path& candidate, const fs::path& root) {
        auto candidateIterator = candidate.begin();
        for (auto rootIterator = root.begin(); rootIterator != root.end(); ++rootIterator, ++candidateIterator) {
            if (candidateIterator == candidate.end() || *candidateIterator != *rootIterator) {
                return false;
            }
        }
        return true;
    }

    bool CreatePrivateDirectoryExclusive(const fs::path& path) {
#ifdef _WIN32
        std::wstring widePath;
        return Utf8ToWide(path.u8string(), widePath) && CreateDirectoryW(widePath.c_str(), nullptr) != 0;
#else
        return mkdir(path.c_str(), 0700) == 0;
#endif
    }

    std::string UniqueToken() {
        std::uint64_t randomness = Utility::GetMicroSecond();
        try {
            std::random_device source;
            randomness ^= static_cast<std::uint64_t>(source()) << 32U;
            randomness ^= static_cast<std::uint64_t>(source());
        } catch (...) {
            // The exclusive create/rename remains the security boundary if an implementation has no random source.
        }
        return std::to_string(randomness);
    }

    bool PathExistsNoFollow(const fs::path& path, bool& exists) {
        std::error_code error;
        const fs::file_status status = fs::symlink_status(path, error);
        if (error == std::errc::no_such_file_or_directory) {
            exists = false;
            return true;
        }
        if (error) {
            return false;
        }
        exists = status.type() != fs::file_type::not_found;
        return true;
    }

    void RecordParentDirectories(const std::string& path, std::set<std::string>& directories) {
        std::size_t separator = path.find('/');
        while (separator != std::string::npos) {
            directories.insert(path.substr(0, separator));
            separator = path.find('/', separator + 1U);
        }
    }

    int OpenArchiveEntry(void* archive, const std::string& relativePath, const zip_fileinfo& info, int compressionLevel,
                         bool zip64) {
        constexpr uLong kUnixVersionMadeBy = (3U << 8U) | 30U;
        constexpr uLong kUtf8NameFlag = 1U << 11U;
        return zipOpenNewFileInZip4_64(archive, relativePath.c_str(), &info, nullptr, 0, nullptr, 0, nullptr,
                                       Z_DEFLATED, compressionLevel, 0, -MAX_WBITS, DEF_MEM_LEVEL, 0, nullptr, 0,
                                       kUnixVersionMadeBy, kUtf8NameFlag, zip64 ? 1 : 0);
    }

    bool IsArchivePathSafe(const std::string& path) {
        if (path.empty() || path.front() == '/' || path.front() == '\\') {
            return false;
        }
        if (path.size() >= 2U && std::isalpha(static_cast<unsigned char>(path[0])) != 0 && path[1] == ':') {
            return false;
        }

        // Reject malformed UTF-8 so path identity is consistent across platforms.
        for (std::size_t index = 0; index < path.size();) {
            const unsigned char lead = static_cast<unsigned char>(path[index]);
            std::size_t continuationCount = 0;
            uint32_t codepoint = 0;
            if (lead <= 0x7FU) {
                ++index;
                continue;
            } else if (lead >= 0xC2U && lead <= 0xDFU) {
                continuationCount = 1;
                codepoint = lead & 0x1FU;
            } else if (lead >= 0xE0U && lead <= 0xEFU) {
                continuationCount = 2;
                codepoint = lead & 0x0FU;
            } else if (lead >= 0xF0U && lead <= 0xF4U) {
                continuationCount = 3;
                codepoint = lead & 0x07U;
            } else {
                return false;
            }
            if (path.size() - index <= continuationCount) {
                return false;
            }
            for (std::size_t offset = 1; offset <= continuationCount; ++offset) {
                const unsigned char continuation = static_cast<unsigned char>(path[index + offset]);
                if ((continuation & 0xC0U) != 0x80U) {
                    return false;
                }
                codepoint = (codepoint << 6U) | (continuation & 0x3FU);
            }
            if ((continuationCount == 2 && codepoint < 0x800U) || (continuationCount == 3 && codepoint < 0x10000U) ||
                codepoint > 0x10FFFFU || (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
                return false;
            }
            index += continuationCount + 1U;
        }

        std::size_t componentStart = 0;
        while (componentStart < path.size()) {
            const std::size_t separator = path.find('/', componentStart);
            const std::size_t componentEnd = separator == std::string::npos ? path.size() : separator;
            if (componentEnd == componentStart) {
                return false;
            }

            const std::string component = path.substr(componentStart, componentEnd - componentStart);
            if (component == "." || component == ".." || component.find(':') != std::string::npos ||
                component.back() == '.' || component.back() == ' ') {
                return false;
            }
            for (const unsigned char character : component) {
                if (character == 0U || character < 0x20U || character == 0x7FU) {
                    return false;
                }
            }

            std::string baseName = component.substr(0, component.find('.'));
            std::transform(baseName.begin(), baseName.end(), baseName.begin(),
                           [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
            static const std::set<std::string> reservedNames = {
                "con",  "prn",  "aux",  "nul",  "com1", "com2", "com3", "com4", "com5", "com6", "com7",
                "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"};
            if (reservedNames.count(baseName) != 0) {
                return false;
            }

            if (separator == std::string::npos) {
                return true;
            }
            componentStart = separator + 1U;
        }
        return false;
    }

    std::string EntryIdentity(std::string path) {
        std::transform(path.begin(), path.end(), path.begin(), [](unsigned char character) {
            return character >= 'A' && character <= 'Z' ? static_cast<char>(character + ('a' - 'A'))
                                                        : static_cast<char>(character);
        });
        return path;
    }

    std::string RelativeArchivePath(const std::string& root, const std::string& path) {
        if (path.size() <= root.size()) {
            return {};
        }

        std::size_t offset = root.size();
        while (offset < path.size() && (path[offset] == '/' || path[offset] == '\\')) {
            ++offset;
        }
        std::string relative = path.substr(offset);
        Utility::StringReplace(relative, "\\", "/");
        return relative;
    }

} // namespace

void ZipArchive::GetModificationTime(const char* path, void* zipFileInfo) {
    auto* info = static_cast<zip_fileinfo*>(zipFileInfo);
    *info = zip_fileinfo{};

    SourceStatus status{};
    if (!GetSourceStatus(path, status)) {
        return;
    }

    struct tm localTime{};
#ifdef _WIN32
    if (localtime_s(&localTime, &status.modificationTime) != 0) {
        return;
    }
#else
    if (localtime_r(&status.modificationTime, &localTime) == nullptr) {
        return;
    }
#endif
    info->tmz_date.tm_sec = localTime.tm_sec;
    info->tmz_date.tm_min = localTime.tm_min;
    info->tmz_date.tm_hour = localTime.tm_hour;
    info->tmz_date.tm_mday = localTime.tm_mday;
    info->tmz_date.tm_mon = localTime.tm_mon;
    info->tmz_date.tm_year = localTime.tm_year + 1900;
    const unsigned int permissions = SanitizedMode(status.mode, status.directory);
    constexpr unsigned int kUnixDirectoryType = 0040000U;
    constexpr unsigned int kUnixRegularType = 0100000U;
    info->external_fa =
        static_cast<uLong>(((status.directory ? kUnixDirectoryType : kUnixRegularType) | permissions) << 16U);
}

bool ZipArchive::AddFile(void* archive, const std::string& sourceFile, const std::string& relativePath,
                         int compressionLevel) {
    SourceStatus sourceStatus{};
    if (!GetSourceStatus(sourceFile, sourceStatus) || !sourceStatus.regular) {
        Logger::ErrorV(">>> ZipArchive: Refusing non-regular source: %s\n", sourceFile.c_str());
        return false;
    }
    FILE* input = nullptr;
    std::uint64_t openedSize = sourceStatus.size;
#ifdef _WIN32
    std::wstring wideSource;
    if (Utf8ToWide(sourceFile, wideSource)) {
        HANDLE sourceHandle = CreateFileW(wideSource.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        BY_HANDLE_FILE_INFORMATION information{};
        LARGE_INTEGER fileSize{};
        if (sourceHandle != INVALID_HANDLE_VALUE && GetFileType(sourceHandle) == FILE_TYPE_DISK &&
            GetFileInformationByHandle(sourceHandle, &information) != 0 &&
            (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
            GetFileSizeEx(sourceHandle, &fileSize) != 0 && fileSize.QuadPart >= 0) {
            openedSize = static_cast<std::uint64_t>(fileSize.QuadPart);
            const int descriptor = _open_osfhandle(reinterpret_cast<intptr_t>(sourceHandle), _O_RDONLY | _O_BINARY);
            if (descriptor >= 0) {
                input = _fdopen(descriptor, "rb");
                if (input == nullptr) {
                    _close(descriptor);
                }
                sourceHandle = INVALID_HANDLE_VALUE; // Descriptor owns the handle, including on fdopen failure.
            }
        }
        if (sourceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(sourceHandle);
        }
    }
#else
    const int inputDescriptor = open(sourceFile.c_str(), O_RDONLY
#ifdef O_NOFOLLOW
                                                             | O_NOFOLLOW
#endif
    );
    if (inputDescriptor >= 0) {
        struct stat openedStatus{};
        if (fstat(inputDescriptor, &openedStatus) == 0 && S_ISREG(openedStatus.st_mode) &&
            openedStatus.st_dev == sourceStatus.device && openedStatus.st_ino == sourceStatus.inode) {
            input = fdopen(inputDescriptor, "rb");
        }
        if (input == nullptr) {
            close(inputDescriptor);
        }
    }
#endif
    if (input == nullptr) {
        Logger::ErrorV(">>> ZipArchive: Could not open file: %s\n", sourceFile.c_str());
        return false;
    }

    zip_fileinfo info{};
    GetModificationTime(sourceFile.c_str(), &info);
    const int openResult = OpenArchiveEntry(archive, relativePath, info, compressionLevel, openedSize > UINT32_MAX);
    if (openResult != ZIP_OK) {
        std::fclose(input);
        Logger::ErrorV(">>> ZipArchive: Could not add file: %s\n", relativePath.c_str());
        return false;
    }

    bool success = true;
    std::vector<char> buffer(64U * 1024U);
    while (true) {
        const std::size_t bytesRead = std::fread(buffer.data(), 1, buffer.size(), input);
        if (bytesRead > 0 && zipWriteInFileInZip(archive, buffer.data(), static_cast<unsigned int>(bytesRead)) < 0) {
            success = false;
            break;
        }
        if (bytesRead < buffer.size()) {
            success = std::ferror(input) == 0;
            break;
        }
    }

    if (zipCloseFileInZip(archive) != ZIP_OK) {
        success = false;
    }
    std::fclose(input);
    return success;
}

bool ZipArchive::AddDirectory(void* archive, const std::string& sourceDirectory, const std::string& relativePath,
                              int compressionLevel) {
    SourceStatus sourceStatus{};
    if (!GetSourceStatus(sourceDirectory, sourceStatus) || !sourceStatus.directory) {
        Logger::ErrorV(">>> ZipArchive: Refusing non-directory source: %s\n", sourceDirectory.c_str());
        return false;
    }
    zip_fileinfo info{};
    GetModificationTime(sourceDirectory.c_str(), &info);
    if (OpenArchiveEntry(archive, relativePath, info, compressionLevel, false) != ZIP_OK) {
        Logger::ErrorV(">>> ZipArchive: Could not add directory: %s\n", relativePath.c_str());
        return false;
    }
    return zipCloseFileInZip(archive) == ZIP_OK;
}

bool ZipArchive::Archive(const std::string& folder, const std::string& archiveFile, int compressionLevel) {
    if (compressionLevel < 0 || compressionLevel > 9 || !FileSystem::IsFolder(folder.c_str())) {
        Logger::ErrorV(">>> ZipArchive: Invalid source folder or compression level: %s (%d)\n", folder.c_str(),
                       compressionLevel);
        return false;
    }

    std::error_code pathError;
    const fs::path sourcePath = fs::weakly_canonical(fs::u8path(folder), pathError);
    if (pathError) {
        return false;
    }
    const fs::path destinationPath = fs::weakly_canonical(fs::u8path(archiveFile), pathError).lexically_normal();
    if (pathError || IsPathWithin(destinationPath, sourcePath)) {
        Logger::ErrorV(">>> ZipArchive: Archive destination must be outside source folder: %s\n", archiveFile.c_str());
        return false;
    }

    const fs::path destinationParent = destinationPath.parent_path();
    fs::path archiveStagingDirectory;
    bool stagingCreated = false;
    const std::string stagingToken = UniqueToken();
    for (unsigned int attempt = 0; attempt < 32 && !stagingCreated; ++attempt) {
        archiveStagingDirectory = destinationParent / (destinationPath.filename().u8string() + ".orchardseal-archive-" +
                                                       stagingToken + "-" + std::to_string(attempt));
        stagingCreated = CreatePrivateDirectoryExclusive(archiveStagingDirectory);
    }
    if (!stagingCreated) {
        return false;
    }
    const fs::path stagedArchivePath = archiveStagingDirectory / "archive.zip";

    zipFile archive = OpenZipForWriting(stagedArchivePath.u8string());
    if (archive == nullptr) {
        FileSystem::RemoveFolder(archiveStagingDirectory.u8string().c_str());
        Logger::ErrorV(">>> ZipArchive: Could not create archive: %s\n", archiveFile.c_str());
        return false;
    }

    bool success = true;
    const bool enumerated =
        FileSystem::EnumFolder(folder.c_str(), true, nullptr, [&](bool directory, const std::string& path) {
            std::string relativePath = RelativeArchivePath(folder, path);
            if (relativePath.empty()) {
                success = false;
                return true;
            }

            if (directory) {
                relativePath.push_back('/');
                success = AddDirectory(archive, path, relativePath, compressionLevel);
            } else {
                success = AddFile(archive, path, relativePath, compressionLevel);
            }
            return !success;
        });

    if (zipClose(archive, nullptr) != ZIP_OK) {
        success = false;
    }
    success = enumerated && success;
    if (!success) {
        FileSystem::RemoveFolder(archiveStagingDirectory.u8string().c_str());
        return false;
    }

    bool hadPreviousArchive = false;
    if (!PathExistsNoFollow(destinationPath, hadPreviousArchive)) {
        FileSystem::RemoveFolder(archiveStagingDirectory.u8string().c_str());
        return false;
    }
    fs::path backupPath;
    fs::path backupContainer;
    if (hadPreviousArchive) {
        bool backedUp = false;
        const std::string backupToken = UniqueToken();
        for (unsigned int attempt = 0; attempt < 32 && !backedUp; ++attempt) {
            backupContainer = destinationParent / (destinationPath.filename().u8string() + ".orchardseal-backup-" +
                                                   backupToken + "-" + std::to_string(attempt));
            if (CreatePrivateDirectoryExclusive(backupContainer)) {
                backupPath = backupContainer / "original";
                pathError.clear();
                fs::rename(destinationPath, backupPath, pathError);
                backedUp = !pathError;
                if (!backedUp) {
                    FileSystem::RemoveFolder(backupContainer.u8string().c_str());
                }
            }
        }
        if (!backedUp) {
            FileSystem::RemoveFolder(archiveStagingDirectory.u8string().c_str());
            return false;
        }
    }
    pathError.clear();
    fs::rename(stagedArchivePath, destinationPath, pathError);
    if (pathError) {
        if (hadPreviousArchive) {
            std::error_code restoreError;
            fs::rename(backupPath, destinationPath, restoreError);
            if (!restoreError) {
                FileSystem::RemoveFolder(backupContainer.u8string().c_str());
            } else {
                Logger::ErrorV(">>> ZipArchive: Previous archive preserved at backup after restore failure: %s\n",
                               backupPath.u8string().c_str());
            }
        }
        FileSystem::RemoveFolder(archiveStagingDirectory.u8string().c_str());
        return false;
    }
    FileSystem::RemoveFolder(archiveStagingDirectory.u8string().c_str());
    if (hadPreviousArchive && !FileSystem::RemoveFolder(backupContainer.u8string().c_str())) {
        Logger::WarnV(">>> ZipArchive: Published archive but could not remove backup: %s\n",
                      backupContainer.u8string().c_str());
    }
    return true;
}

bool ZipArchive::EnumerateEntries(const char* archiveFile, const EntryCallback& callback) {
    unzFile archive = OpenZipForReading(archiveFile);
    if (archive == nullptr) {
        return false;
    }

    unz_global_info64 globalInfo{};
    if (unzGetGlobalInfo64(archive, &globalInfo) != UNZ_OK) {
        unzClose(archive);
        return false;
    }
    if (globalInfo.number_entry > kMaximumEntryCount) {
        unzClose(archive);
        return false;
    }

    bool success = true;
    for (std::uint64_t index = 0; index < globalInfo.number_entry; ++index) {
        unz_file_info64 fileInfo{};
        if (unzGetCurrentFileInfo64(archive, &fileInfo, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK ||
            fileInfo.size_filename == 0 || fileInfo.size_filename > kMaximumEntryPathLength) {
            success = false;
            break;
        }

        std::vector<char> pathBuffer(static_cast<std::size_t>(fileInfo.size_filename) + 1U, '\0');
        if (unzGetCurrentFileInfo64(archive, &fileInfo, pathBuffer.data(), static_cast<uLong>(pathBuffer.size()),
                                    nullptr, 0, nullptr, 0) != UNZ_OK) {
            success = false;
            break;
        }

        std::string path(pathBuffer.data(), static_cast<std::size_t>(fileInfo.size_filename));
        Utility::StringReplace(path, "\\", "/");
        bool directory = false;
        if (!path.empty() && path.back() == '/') {
            directory = true;
            path.pop_back();
        }

        if (path.empty() || (callback && !callback(archive, directory, path))) {
            success = false;
            break;
        }
        if (index + 1U < globalInfo.number_entry && unzGoToNextFile(archive) != UNZ_OK) {
            success = false;
            break;
        }
    }

    unzClose(archive);
    return success;
}

bool ZipArchive::ExtractEntry(void* archive, const std::string& path, const std::string& outputFolder,
                              std::uint64_t expectedSize, std::uint64_t& totalWritten, unsigned int mode) {
    const std::string outputFile = outputFolder + "/" + path;
    std::string parentDirectory = outputFile;
    if (!FileSystem::PathRemoveFileSpec(parentDirectory) || !FileSystem::CreateFolder(parentDirectory.c_str())) {
        return false;
    }
    if (unzOpenCurrentFile(archive) != UNZ_OK) {
        return false;
    }

    FILE* output = nullptr;
#ifdef _WIN32
    std::wstring wideOutput;
    if (Utf8ToWide(outputFile, wideOutput)) {
        const int descriptor =
            _wopen(wideOutput.c_str(), _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
        if (descriptor >= 0) {
            output = _fdopen(descriptor, "wb");
            if (output == nullptr) {
                _close(descriptor);
            }
        }
    }
#else
    const int descriptor = open(outputFile.c_str(),
                                O_CREAT | O_EXCL | O_WRONLY
#ifdef O_NOFOLLOW
                                    | O_NOFOLLOW
#endif
                                ,
                                0600);
    if (descriptor >= 0) {
        output = fdopen(descriptor, "wb");
        if (output == nullptr) {
            close(descriptor);
        }
    }
#endif
    if (output == nullptr) {
        unzCloseCurrentFile(archive);
        return false;
    }

    bool success = true;
    std::uint64_t entryWritten = 0;
    std::vector<char> buffer(kExtractionBufferSize);
    while (true) {
        const int bytesRead = unzReadCurrentFile(archive, buffer.data(), static_cast<unsigned int>(buffer.size()));
        if (bytesRead < 0) {
            success = false;
            break;
        }
        if (bytesRead == 0) {
            break;
        }
        if (static_cast<std::uint64_t>(bytesRead) > expectedSize - std::min(expectedSize, entryWritten) ||
            totalWritten > kMaximumTotalSize - static_cast<std::uint64_t>(bytesRead)) {
            success = false;
            break;
        }
        if (std::fwrite(buffer.data(), 1, static_cast<std::size_t>(bytesRead), output) !=
            static_cast<std::size_t>(bytesRead)) {
            success = false;
            break;
        }
        entryWritten += static_cast<std::uint64_t>(bytesRead);
        totalWritten += static_cast<std::uint64_t>(bytesRead);
    }

    if (std::fclose(output) != 0) {
        success = false;
    }
    if (unzCloseCurrentFile(archive) != UNZ_OK) {
        success = false;
    }
    if (success && entryWritten != expectedSize) {
        success = false;
    }
#ifndef _WIN32
    if (success && chmod(outputFile.c_str(), SanitizedMode(mode, false)) != 0) {
        success = false;
    }
#endif
    if (!success) {
        FileSystem::RemoveFile(outputFile.c_str());
    }
    return success;
}

bool ZipArchive::ExtractEntries(const char* archiveFile, const char* outputFolder) {
    std::set<std::string> seenEntries;
    std::set<std::string> materializedDirectories;
    std::uint64_t declaredTotal = 0;
    std::uint64_t actualTotal = 0;
    return EnumerateEntries(archiveFile, [&](void* archive, bool directory, const std::string& path) {
        if (!IsArchivePathSafe(path)) {
            Logger::ErrorV(">>> ZipArchive: Refusing unsafe archive path: %s\n", path.c_str());
            return false;
        }
        if (!seenEntries.insert(EntryIdentity(path)).second) {
            Logger::ErrorV(">>> ZipArchive: Refusing duplicate archive path: %s\n", path.c_str());
            return false;
        }

        unz_file_info64 info{};
        if (unzGetCurrentFileInfo64(archive, &info, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK ||
            info.uncompressed_size > kMaximumEntrySize || info.uncompressed_size > kMaximumTotalSize - declaredTotal) {
            Logger::ErrorV(">>> ZipArchive: Entry exceeds extraction limits: %s\n", path.c_str());
            return false;
        }
        if (info.uncompressed_size > 0 &&
            (info.compressed_size == 0 ||
             info.compressed_size <
                 (info.uncompressed_size + kMaximumCompressionRatio - 1U) / kMaximumCompressionRatio)) {
            Logger::ErrorV(">>> ZipArchive: Suspicious compression ratio: %s\n", path.c_str());
            return false;
        }
        declaredTotal += info.uncompressed_size;

        const unsigned int archivedMode = static_cast<unsigned int>(info.external_fa >> 16U);
        const unsigned int archivedType = archivedMode & 0170000U;
        if (archivedType == 0120000U || (archivedType != 0U && archivedType != 0100000U && archivedType != 0040000U)) {
            Logger::ErrorV(">>> ZipArchive: Refusing special or symbolic-link entry: %s\n", path.c_str());
            return false;
        }

        if (directory) {
            const std::string destination = std::string(outputFolder) + "/" + path;
            if (FileSystem::IsFileExists(destination.c_str()) && materializedDirectories.count(path) == 0) {
                Logger::ErrorV(">>> ZipArchive: Refusing colliding archive path: %s\n", path.c_str());
                return false;
            }
            if (archivedType == 0100000U || !FileSystem::CreateFolderV("%s/%s", outputFolder, path.c_str())) {
                return false;
            }
            materializedDirectories.insert(path);
            RecordParentDirectories(path, materializedDirectories);
#ifndef _WIN32
            return chmod(destination.c_str(), SanitizedMode(archivedMode, true)) == 0;
#else
            return true;
#endif
        }
        if (archivedType == 0040000U) {
            return false;
        }
        const bool extracted =
            ExtractEntry(archive, path, outputFolder, info.uncompressed_size, actualTotal, archivedMode);
        if (extracted) {
            RecordParentDirectories(path, materializedDirectories);
        }
        return extracted;
    });
}

bool ZipArchive::Extract(const char* archiveFile, const char* outputFolder) {
    if (archiveFile == nullptr || outputFolder == nullptr || *archiveFile == '\0' || *outputFolder == '\0') {
        return false;
    }

    std::error_code pathError;
    const fs::path outputPath = fs::weakly_canonical(fs::u8path(outputFolder), pathError).lexically_normal();
    const fs::path archivePath = fs::weakly_canonical(fs::u8path(archiveFile), pathError);
    if (pathError || IsPathWithin(archivePath, outputPath)) {
        return false;
    }
    const fs::path parentPath = outputPath.parent_path();
    if (parentPath.empty() || !FileSystem::CreateFolder(parentPath.u8string().c_str())) {
        return false;
    }

    fs::path stagingPath;
    bool stagingCreated = false;
    const std::string stagingToken = UniqueToken();
    for (unsigned int attempt = 0; attempt < 32 && !stagingCreated; ++attempt) {
        stagingPath = parentPath / (outputPath.filename().u8string() + ".orchardseal-staging-" + stagingToken + "-" +
                                    std::to_string(attempt));
        stagingCreated = CreatePrivateDirectoryExclusive(stagingPath);
    }
    if (!stagingCreated) {
        return false;
    }
    if (!ExtractEntries(archiveFile, stagingPath.u8string().c_str())) {
        FileSystem::RemoveFolder(stagingPath.u8string().c_str());
        return false;
    }
#ifndef _WIN32
    if (chmod(stagingPath.c_str(), 0755) != 0) {
        FileSystem::RemoveFolder(stagingPath.u8string().c_str());
        return false;
    }
#endif

    bool hadPreviousOutput = false;
    if (!PathExistsNoFollow(outputPath, hadPreviousOutput)) {
        FileSystem::RemoveFolder(stagingPath.u8string().c_str());
        return false;
    }

    fs::path backupPath;
    fs::path backupContainer;
    if (hadPreviousOutput) {
        bool backedUp = false;
        const std::string backupToken = UniqueToken();
        for (unsigned int attempt = 0; attempt < 32 && !backedUp; ++attempt) {
            backupContainer = parentPath / (outputPath.filename().u8string() + ".orchardseal-backup-" + backupToken +
                                            "-" + std::to_string(attempt));
            if (CreatePrivateDirectoryExclusive(backupContainer)) {
                backupPath = backupContainer / "original";
                fs::rename(outputPath, backupPath, pathError);
                backedUp = !pathError;
                if (!backedUp) {
                    FileSystem::RemoveFolder(backupContainer.u8string().c_str());
                }
            }
        }
        if (!backedUp) {
            FileSystem::RemoveFolder(stagingPath.u8string().c_str());
            return false;
        }
    }

    pathError.clear();
    fs::rename(stagingPath, outputPath, pathError);
    if (pathError) {
        if (hadPreviousOutput) {
            std::error_code restoreError;
            fs::rename(backupPath, outputPath, restoreError);
            if (restoreError) {
                Logger::ErrorV(">>> ZipArchive: Failed to restore previous output after publish failure: %s\n",
                               outputFolder);
            } else {
                FileSystem::RemoveFolder(backupContainer.u8string().c_str());
            }
        }
        FileSystem::RemoveFolder(stagingPath.u8string().c_str());
        return false;
    }
    if (hadPreviousOutput && !FileSystem::RemoveFolder(backupContainer.u8string().c_str())) {
        Logger::WarnV(">>> ZipArchive: Published output but could not remove backup: %s\n",
                      backupContainer.u8string().c_str());
    }
    return true;
}
