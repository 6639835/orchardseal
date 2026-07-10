#include "zip_archive.h"

#include "common.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
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

namespace {

constexpr std::uint64_t kMaximumEntryPathLength = 64U * 1024U;
constexpr std::size_t kExtractionBufferSize = 512U * 1024U;

bool IsArchivePathSafe(const std::string& path)
{
    if (path.empty() || path.front() == '/' || path.front() == '\\') {
        return false;
    }
    if (path.size() >= 2U && std::isalpha(static_cast<unsigned char>(path[0])) != 0 && path[1] == ':') {
        return false;
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

        if (separator == std::string::npos) {
            return true;
        }
        componentStart = separator + 1U;
    }
    return false;
}

std::string EntryIdentity(std::string path)
{
#ifdef _WIN32
    std::transform(path.begin(), path.end(), path.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
#endif
    return path;
}

std::string RelativeArchivePath(const std::string& root, const std::string& path)
{
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

void ZipArchive::GetModificationTime(const char* path, void* zipFileInfo)
{
    auto* info = static_cast<zip_fileinfo*>(zipFileInfo);
    *info = zip_fileinfo {};

    struct stat status {};
    if (stat(path, &status) != 0) {
        return;
    }

    struct tm localTime {};
#ifdef _WIN32
    if (localtime_s(&localTime, &status.st_mtime) != 0) {
        return;
    }
#else
    if (localtime_r(&status.st_mtime, &localTime) == nullptr) {
        return;
    }
#endif
    info->tmz_date.tm_sec = localTime.tm_sec;
    info->tmz_date.tm_min = localTime.tm_min;
    info->tmz_date.tm_hour = localTime.tm_hour;
    info->tmz_date.tm_mday = localTime.tm_mday;
    info->tmz_date.tm_mon = localTime.tm_mon;
    info->tmz_date.tm_year = localTime.tm_year + 1900;
}

bool ZipArchive::AddFile(void* archive,
                         const std::string& sourceFile,
                         const std::string& relativePath,
                         int compressionLevel)
{
    FILE* input = nullptr;
    _fopen64(input, sourceFile.c_str(), "rb");
    if (input == nullptr) {
        Logger::ErrorV(">>> ZipArchive: Could not open file: %s\n", sourceFile.c_str());
        return false;
    }

    zip_fileinfo info {};
    GetModificationTime(sourceFile.c_str(), &info);
    const int openResult = zipOpenNewFileInZip3_64(archive,
                                                   relativePath.c_str(),
                                                   &info,
                                                   nullptr,
                                                   0,
                                                   nullptr,
                                                   0,
                                                   nullptr,
                                                   Z_DEFLATED,
                                                   compressionLevel,
                                                   0,
                                                   -MAX_WBITS,
                                                   DEF_MEM_LEVEL,
                                                   0,
                                                   nullptr,
                                                   0,
                                                   0);
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

bool ZipArchive::AddDirectory(void* archive,
                              const std::string& sourceDirectory,
                              const std::string& relativePath,
                              int compressionLevel)
{
    zip_fileinfo info {};
    GetModificationTime(sourceDirectory.c_str(), &info);
    if (zipOpenNewFileInZip3_64(archive,
                                relativePath.c_str(),
                                &info,
                                nullptr,
                                0,
                                nullptr,
                                0,
                                nullptr,
                                Z_DEFLATED,
                                compressionLevel,
                                0,
                                -MAX_WBITS,
                                DEF_MEM_LEVEL,
                                0,
                                nullptr,
                                0,
                                0) != ZIP_OK) {
        Logger::ErrorV(">>> ZipArchive: Could not add directory: %s\n", relativePath.c_str());
        return false;
    }
    return zipCloseFileInZip(archive) == ZIP_OK;
}

bool ZipArchive::Archive(const std::string& folder, const std::string& archiveFile, int compressionLevel)
{
    if (compressionLevel < 0 || compressionLevel > 9 || !FileSystem::IsFolder(folder.c_str())) {
        Logger::ErrorV(">>> ZipArchive: Invalid source folder or compression level: %s (%d)\n",
                       folder.c_str(),
                       compressionLevel);
        return false;
    }

    zipFile archive = zipOpen64(archiveFile.c_str(), APPEND_STATUS_CREATE);
    if (archive == nullptr) {
        Logger::ErrorV(">>> ZipArchive: Could not create archive: %s\n", archiveFile.c_str());
        return false;
    }

    bool success = true;
    const bool enumerated = FileSystem::EnumFolder(
        folder.c_str(), true, nullptr, [&](bool directory, const std::string& path) {
            std::string relativePath = RelativeArchivePath(folder, path);
            if (relativePath.empty()) {
                success = false;
                return true;
            }

#ifdef _WIN32
            WindowsTextConverter converter;
            relativePath = converter.AnsiToUtf8(relativePath);
#endif

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
    return enumerated && success;
}

bool ZipArchive::EnumerateEntries(const char* archiveFile, const EntryCallback& callback)
{
    unzFile archive = unzOpen64(archiveFile);
    if (archive == nullptr) {
        return false;
    }

    unz_global_info64 globalInfo {};
    if (unzGetGlobalInfo64(archive, &globalInfo) != UNZ_OK) {
        unzClose(archive);
        return false;
    }

    bool success = true;
    for (std::uint64_t index = 0; index < globalInfo.number_entry; ++index) {
        unz_file_info64 fileInfo {};
        if (unzGetCurrentFileInfo64(archive, &fileInfo, nullptr, 0, nullptr, 0, nullptr, 0) != UNZ_OK ||
            fileInfo.size_filename == 0 || fileInfo.size_filename > kMaximumEntryPathLength) {
            success = false;
            break;
        }

        std::vector<char> pathBuffer(static_cast<std::size_t>(fileInfo.size_filename) + 1U, '\0');
        if (unzGetCurrentFileInfo64(archive,
                                    &fileInfo,
                                    pathBuffer.data(),
                                    static_cast<uLong>(pathBuffer.size()),
                                    nullptr,
                                    0,
                                    nullptr,
                                    0) != UNZ_OK) {
            success = false;
            break;
        }

        std::string path(pathBuffer.data(), static_cast<std::size_t>(fileInfo.size_filename));
        Utility::StringReplace(path, "\\", "/");
#ifdef _WIN32
        WindowsTextConverter converter;
        path = converter.Utf8ToAnsi(path);
#endif

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

bool ZipArchive::ExtractEntry(void* archive, const std::string& path, const std::string& outputFolder)
{
    const std::string outputFile = outputFolder + "/" + path;
    std::string parentDirectory = outputFile;
    if (!FileSystem::PathRemoveFileSpec(parentDirectory) || !FileSystem::CreateFolder(parentDirectory.c_str())) {
        return false;
    }
    if (unzOpenCurrentFile(archive) != UNZ_OK) {
        return false;
    }

    FILE* output = nullptr;
    _fopen64(output, outputFile.c_str(), "wb");
    if (output == nullptr) {
        unzCloseCurrentFile(archive);
        return false;
    }

    bool success = true;
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
        if (std::fwrite(buffer.data(), 1, static_cast<std::size_t>(bytesRead), output) !=
            static_cast<std::size_t>(bytesRead)) {
            success = false;
            break;
        }
    }

    if (std::fclose(output) != 0) {
        success = false;
    }
    if (unzCloseCurrentFile(archive) != UNZ_OK) {
        success = false;
    }
    return success;
}

bool ZipArchive::ExtractEntries(const char* archiveFile, const char* outputFolder)
{
    std::set<std::string> seenEntries;
    return EnumerateEntries(archiveFile, [&](void* archive, bool directory, const std::string& path) {
        if (!IsArchivePathSafe(path)) {
            Logger::ErrorV(">>> ZipArchive: Refusing unsafe archive path: %s\n", path.c_str());
            return false;
        }
        if (!seenEntries.insert(EntryIdentity(path)).second) {
            Logger::ErrorV(">>> ZipArchive: Refusing duplicate archive path: %s\n", path.c_str());
            return false;
        }

        if (directory) {
            return FileSystem::CreateFolderV("%s/%s", outputFolder, path.c_str());
        }
        return ExtractEntry(archive, path, outputFolder);
    });
}

bool ZipArchive::Extract(const char* archiveFile, const char* outputFolder)
{
    if (archiveFile == nullptr || outputFolder == nullptr || *archiveFile == '\0' || *outputFolder == '\0') {
        return false;
    }

    FileSystem::RemoveFolder(outputFolder);
    if (!ExtractEntries(archiveFile, outputFolder)) {
        FileSystem::RemoveFolder(outputFolder);
        return false;
    }
    return true;
}
