#pragma once

#include <functional>
#include <string>

class ZipArchive final {
  public:
    static bool Archive(const std::string& folder, const std::string& archiveFile, int compressionLevel);
    static bool Extract(const char* archiveFile, const char* outputFolder);

  private:
    using EntryCallback = std::function<bool(void* archive, bool directory, const std::string& path)>;

    static bool EnumerateEntries(const char* archiveFile, const EntryCallback& callback);
    static bool ExtractEntry(void* archive, const std::string& path, const std::string& outputFolder,
                             std::uint64_t expectedSize, std::uint64_t& totalWritten, unsigned int mode);
    static bool ExtractEntries(const char* archiveFile, const char* outputFolder);
    static bool AddFile(void* archive, const std::string& sourceFile, const std::string& relativePath,
                        int compressionLevel);
    static bool AddDirectory(void* archive, const std::string& sourceDirectory, const std::string& relativePath,
                             int compressionLevel);
    static void GetModificationTime(const char* path, void* zipFileInfo);
};
