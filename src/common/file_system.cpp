#include "file_system.h"

#include <filesystem>
#include <limits>

#if defined(__APPLE__)
#include <sys/stdio.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#endif

#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

map<void*, void*> FileSystem::s_mapFiles;

#ifdef _WIN32
namespace {
    bool Utf8ToWide(const char* input, std::wstring& output) {
        output.clear();
        if (input == nullptr || *input == '\0') {
            return false;
        }
        const int length = static_cast<int>(strlen(input));
        const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, length, nullptr, 0);
        if (count <= 0) {
            return false;
        }
        output.resize(static_cast<size_t>(count));
        return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, length, output.data(), count) == count;
    }

    bool WideToUtf8(const wchar_t* input, std::string& output) {
        output.clear();
        if (input == nullptr) {
            return false;
        }
        const int length = static_cast<int>(wcslen(input));
        if (length == 0) {
            return true;
        }
        const int count =
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, length, nullptr, 0, nullptr, nullptr);
        if (count <= 0) {
            return false;
        }
        output.resize(static_cast<size_t>(count));
        return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, length, output.data(), count, nullptr,
                                   nullptr) == count;
    }

    FILE* OpenFileUtf8(const char* path, const wchar_t* mode) {
        std::wstring widePath;
        if (!Utf8ToWide(path, widePath)) {
            return nullptr;
        }
        FILE* result = nullptr;
        return _wfopen_s(&result, widePath.c_str(), mode) == 0 ? result : nullptr;
    }

    bool IsDirectoryTreeSafe(const std::wstring& path) {
        std::filesystem::path current(path);
        while (!current.empty()) {
            const DWORD attributes = GetFileAttributesW(current.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES &&
                ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)) {
                return false;
            }
            const std::filesystem::path parent = current.parent_path();
            if (parent == current) {
                break;
            }
            current = parent;
        }
        return true;
    }
} // namespace
#endif

bool FileSystem::IsRegularFile(const char* path) {
#ifdef _WIN32
    std::wstring widePath;
    if (!Utf8ToWide(path, widePath)) {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(widePath.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
#else
    struct stat st = {0};
    return path != nullptr && 0 == lstat(path, &st) && S_ISREG(st.st_mode);
#endif
}

void* FileSystem::MapFile(const char* path, size_t offset, size_t size, size_t* mappedSize, bool readOnly) {
    if (mappedSize != nullptr) {
        *mappedSize = 0;
    }
    if (path == nullptr || *path == '\0') {
        return nullptr;
    }

#ifdef _WIN32
    const DWORD access = readOnly ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    const DWORD sharing = readOnly ? FILE_SHARE_READ : (FILE_SHARE_READ | FILE_SHARE_WRITE);
    std::wstring widePath;
    if (!Utf8ToWide(path, widePath)) {
        return nullptr;
    }
    HANDLE file = ::CreateFileW(widePath.c_str(), access, sharing, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    BY_HANDLE_FILE_INFORMATION information{};
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &information) ||
        (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        ::CloseHandle(file);
        return nullptr;
    }

    LARGE_INTEGER fileSize{};
    if (!::GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0 ||
        static_cast<unsigned long long>(offset) > static_cast<unsigned long long>(fileSize.QuadPart)) {
        ::CloseHandle(file);
        return nullptr;
    }

    const unsigned long long available = static_cast<unsigned long long>(fileSize.QuadPart) - offset;
    if (size == 0) {
        if (available > static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
            ::CloseHandle(file);
            return nullptr;
        }
        size = static_cast<size_t>(available);
    }
    if (size == 0 || static_cast<unsigned long long>(size) > available) {
        ::CloseHandle(file);
        return nullptr;
    }

    HANDLE mapping = ::CreateFileMappingA(file, nullptr, readOnly ? PAGE_READONLY : PAGE_READWRITE, 0, 0, nullptr);
    if (mapping == nullptr) {
        ::CloseHandle(file);
        return nullptr;
    }

    const unsigned long long offsetValue = offset;
    void* base =
        ::MapViewOfFile(mapping, readOnly ? FILE_MAP_READ : FILE_MAP_ALL_ACCESS, static_cast<DWORD>(offsetValue >> 32U),
                        static_cast<DWORD>(offsetValue & 0xffffffffU), size);
    ::CloseHandle(file);
    if (base == nullptr) {
        ::CloseHandle(mapping);
        return nullptr;
    }

    s_mapFiles[base] = mapping;
#else
    const int descriptor = open(path, (readOnly ? O_RDONLY : O_RDWR)
#ifdef O_NOFOLLOW
                                          | O_NOFOLLOW
#endif
    );
    if (descriptor < 0) {
        return nullptr;
    }

    struct stat fileStatus{};
    if (fstat(descriptor, &fileStatus) != 0 || !S_ISREG(fileStatus.st_mode) || fileStatus.st_size < 0 ||
        static_cast<uint64_t>(offset) > static_cast<uint64_t>(fileStatus.st_size)) {
        close(descriptor);
        return nullptr;
    }

    const uint64_t available = static_cast<uint64_t>(fileStatus.st_size) - offset;
    if (size == 0) {
        if (available > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
            close(descriptor);
            return nullptr;
        }
        size = static_cast<size_t>(available);
    }
    if (size == 0 || static_cast<uint64_t>(size) > available) {
        close(descriptor);
        return nullptr;
    }

    void* base = mmap(nullptr, size, readOnly ? PROT_READ : (PROT_READ | PROT_WRITE), MAP_SHARED, descriptor,
                      static_cast<off_t>(offset));
    close(descriptor);
    if (base == MAP_FAILED) {
        return nullptr;
    }
#endif

    if (mappedSize != nullptr) {
        *mappedSize = size;
    }
    return base;
}

bool FileSystem::UnmapFile(void* base, size_t size) {
#ifdef _WIN32
    auto it = s_mapFiles.find(base);
    if (it != s_mapFiles.end()) {
        ::UnmapViewOfFile(base);
        ::CloseHandle(it->second);
        s_mapFiles.erase(it);
        return true;
    }
    return false;
#else
    return (0 == munmap(base, size));
#endif
}

bool FileSystem::WriteFile(const char* szFile, const char* szData, size_t sLen) {
    if (NULL == szFile) {
        return false;
    }

    FILE* fp = NULL;
#ifdef _WIN32
    fp = OpenFileUtf8(szFile, L"wb");
#else
    _fopen64(fp, szFile, "wb");
#endif
    if (NULL != fp) {
        size_t written = 0;
        size_t to_write = sLen;
        if (NULL != szData) {
            while (written < to_write) {
                size_t ret = fwrite(szData + written, 1, to_write - written, fp);
                if (ret <= 0) {
                    break;
                }
                written += ret;
            }
        }
        fclose(fp);
        return (written == to_write);
    } else {
        Logger::ErrorV("WriteFile: Failed in fopen! %s, %s\n", szFile, strerror(errno));
    }
    return false;
}

bool FileSystem::WriteFile(const char* szFile, const string& strData) {
    return WriteFile(szFile, strData.data(), strData.size());
}

bool FileSystem::WriteFileV(const string& strData, const char* szPath, ...) {
    FORMAT_V(szPath, szRealPath);
    return WriteFile(szRealPath, strData);
}

bool FileSystem::WriteFileV(const char* szData, size_t sLen, const char* szPath, ...) {
    FORMAT_V(szPath, szRealPath);
    return WriteFile(szRealPath, szData, sLen);
}

bool FileSystem::ReadFile(const char* szFile, string& strData) {
    strData.clear();
    if (NULL == szFile) {
        return false;
    }

    FILE* fp = NULL;
#ifdef _WIN32
    fp = OpenFileUtf8(szFile, L"rb");
#else
    _fopen64(fp, szFile, "rb");
#endif
    if (NULL != fp) {
        if (0 != _fseeki64(fp, 0, SEEK_END)) {
            fclose(fp);
            return false;
        }
        int64_t to_read = _ftelli64(fp);
        if (to_read < 0 || 0 != _fseeki64(fp, 0, SEEK_SET)) {
            fclose(fp);
            return false;
        }

        strData.resize((size_t)to_read);
        int64_t readed = 0;
        while (readed < to_read) {
            size_t ret = fread(&(strData[(size_t)readed]), 1, (size_t)(to_read - readed), fp);
            if (ret <= 0) {
                break;
            }
            readed += (int64_t)ret;
        }

        fclose(fp);
        if (readed != to_read) {
            strData.clear();
            return false;
        }
        return true;
    }
    return false;
}

bool FileSystem::ReadFileV(string& strData, const char* szPath, ...) {
    FORMAT_V(szPath, szRealPath);
    return FileSystem::ReadFile(szRealPath, strData);
}

bool FileSystem::AppendFile(const char* szFile, const char* szData, size_t sLen) {
    FILE* fp = NULL;
#ifdef _WIN32
    fp = OpenFileUtf8(szFile, L"ab+");
#else
    _fopen64(fp, szFile, "ab+");
#endif
    if (NULL != fp) {
        int64_t towrite = sLen;
        while (towrite > 0) {
            int64_t nwrite = fwrite(szData + (sLen - towrite), 1, towrite, fp);
            if (nwrite <= 0) {
                break;
            }
            towrite -= nwrite;
        }

        fclose(fp);
        return (towrite > 0) ? false : true;
    } else {
        Logger::ErrorV("AppendFile: Failed in fopen! %s, %s\n", szFile, strerror(errno));
    }
    return false;
}

bool FileSystem::AppendFile(const char* szFile, const string& strData) {
    return AppendFile(szFile, strData.data(), strData.size());
}

bool FileSystem::IsFolder(const char* szFolder) {
#ifdef _WIN32
    std::wstring widePath;
    if (!Utf8ToWide(szFolder, widePath)) {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(widePath.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
#else
    struct stat st = {0};
    return 0 == stat(szFolder, &st) && S_ISDIR(st.st_mode);
#endif
}

bool FileSystem::IsFolderV(const char* szPath, ...) {
    FORMAT_V(szPath, szFolder);
    return IsFolder(szFolder);
}

bool FileSystem::CreateFolder(const char* szFolder) {
    if (szFolder == nullptr || *szFolder == '\0') {
        return false;
    }
    string strPath = GetFullPath(szFolder);
#ifdef _WIN32
    std::wstring widePath;
    if (!Utf8ToWide(strPath.c_str(), widePath) || !IsDirectoryTreeSafe(widePath)) {
        return false;
    }
    std::error_code createError;
    std::filesystem::create_directories(std::filesystem::path(widePath), createError);
    if (createError || !IsDirectoryTreeSafe(widePath)) {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(widePath.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
           (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
#else
    if (!IsFolder(strPath.c_str())) {
        size_t pos = 0;
        pos = strPath.find('/', pos);
        while (string::npos != pos) {
            string strFolder = strPath.substr(0, pos++);
            if (!strFolder.empty()) {
                if (0 != mkdir(strFolder.c_str(), 0755)) {
                    if (EEXIST != errno) {
                        return false;
                    }
                    struct stat status{};
                    if (stat(strFolder.c_str(), &status) != 0 || !S_ISDIR(status.st_mode)) {
                        return false;
                    }
                }
            }
            pos = strPath.find('/', pos);
        }
        if (0 != mkdir(strPath.c_str(), 0755)) {
            if (EEXIST != errno) {
                return false;
            }
            struct stat status{};
            if (stat(strPath.c_str(), &status) != 0 || !S_ISDIR(status.st_mode)) {
                return false;
            }
        }
        return true;
    }
    return true;
#endif
}

bool FileSystem::CreateFolderV(const char* szPath, ...) {
    FORMAT_V(szPath, szFolder);
    return CreateFolder(szFolder);
}

int FileSystem::RemoveFolderCallBack(const char* fpath, const struct stat* sb, int typeflag, struct FTW* ftwbuf) {
    int ret = remove(fpath);
    if (ret) {
        perror(fpath);
    }
    return ret;
}

bool FileSystem::RemoveFolder(const char* szFolder) {
    if (NULL == szFolder) {
        return false;
    }

#ifdef _WIN32
    std::wstring strFolder;
    if (!Utf8ToWide(szFolder, strFolder)) {
        return false;
    }
    const DWORD attributes = GetFileAttributesW(strFolder.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return false;
    }
    if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? RemoveDirectoryW(strFolder.c_str()) != 0
                                                            : DeleteFileW(strFolder.c_str()) != 0;
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return DeleteFileW(strFolder.c_str()) != 0;
    }
    std::error_code removeError;
    const std::uintmax_t removed = std::filesystem::remove_all(std::filesystem::path(strFolder), removeError);
    return !removeError && removed > 0;
#else
    if (!IsFolder(szFolder)) {
        return RemoveFile(szFolder);
    }
    return (0 == nftw(szFolder, RemoveFolderCallBack, 64, FTW_DEPTH | FTW_PHYS));
#endif
}

bool FileSystem::RemoveFolderV(const char* szPath, ...) {
    FORMAT_V(szPath, szFolder);
    return RemoveFolder(szFolder);
}

bool FileSystem::RemoveFile(const char* szFile) {
#ifdef _WIN32
    std::wstring widePath;
    return Utf8ToWide(szFile, widePath) && DeleteFileW(widePath.c_str()) != 0;
#else
    return (NULL != szFile && 0 == remove(szFile));
#endif
}

bool FileSystem::RemoveFileV(const char* szPath, ...) {
    FORMAT_V(szPath, szFile);
    return RemoveFile(szFile);
}

bool FileSystem::IsFileExists(const char* szFile) {
    if (NULL == szFile) {
        return false;
    }

#ifdef _WIN32
    std::wstring widePath;
    return Utf8ToWide(szFile, widePath) && GetFileAttributesW(widePath.c_str()) != INVALID_FILE_ATTRIBUTES;
#else
    return (0 == access(szFile, F_OK));
#endif
}

bool FileSystem::IsFileExistsV(const char* szPath, ...) {
    FORMAT_V(szPath, szFile);
    return IsFileExists(szFile);
}

bool FileSystem::IsZipFile(const char* szFile) {
    if (NULL != szFile && !IsFolder(szFile)) {
        FILE* fp = NULL;
#ifdef _WIN32
        fp = OpenFileUtf8(szFile, L"rb");
#else
        _fopen64(fp, szFile, "rb");
#endif
        if (NULL != fp) {
            uint8_t buf[2] = {0};
            const size_t bytesRead = fread(buf, 1, sizeof(buf), fp);
            fclose(fp);
            return bytesRead == sizeof(buf) && (0 == memcmp("PK", buf, sizeof(buf)));
        }
    }
    return false;
}

bool FileSystem::CopyFile(const char* szSrcFile, const char* szDestFile) {
    if (NULL == szSrcFile || NULL == szDestFile) {
        return false;
    }

#ifdef _WIN32
    std::wstring wideSource;
    std::wstring wideDestination;
    return Utf8ToWide(szSrcFile, wideSource) && Utf8ToWide(szDestFile, wideDestination) &&
           ::CopyFileW(wideSource.c_str(), wideDestination.c_str(), FALSE) != 0;
#else

    int src_id = open(szSrcFile, O_RDONLY);
    if (-1 == src_id) {
        return false;
    }

    int dest_fd = open(szDestFile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (-1 == dest_fd) {
        close(src_id);
        return false;
    }

    bool ok = true;
    char buffer[65536];
    ssize_t bytes_read = 0;
    while ((bytes_read = read(src_id, buffer, sizeof(buffer))) > 0) {
        ssize_t total_written = 0;
        while (total_written < bytes_read) {
            ssize_t bytes_written = write(dest_fd, buffer + total_written, (size_t)(bytes_read - total_written));
            if (bytes_written <= 0) {
                ok = false;
                break;
            }
            total_written += bytes_written;
        }
        if (!ok) {
            break;
        }
    }

    if (bytes_read < 0) {
        ok = false;
    }

    close(dest_fd);
    close(src_id);
    return ok;

#endif
}

bool FileSystem::CopyFileV(const char* szSrcFile, const char* szDestPath, ...) {
    FORMAT_V(szDestPath, szDestFile);
    return CopyFile(szSrcFile, szDestFile);
}

bool FileSystem::Rename(const char* source, const char* destination, bool replaceExisting) {
    if (source == nullptr || destination == nullptr || *source == '\0' || *destination == '\0') {
        return false;
    }
#ifdef _WIN32
    std::wstring wideSource;
    std::wstring wideDestination;
    if (!Utf8ToWide(source, wideSource) || !Utf8ToWide(destination, wideDestination)) {
        return false;
    }
    DWORD flags = MOVEFILE_WRITE_THROUGH;
    if (replaceExisting) {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    return MoveFileExW(wideSource.c_str(), wideDestination.c_str(), flags) != 0;
#else
    if (replaceExisting) {
        return ::rename(source, destination) == 0;
    }
#if defined(__APPLE__)
    return ::renamex_np(source, destination, RENAME_EXCL) == 0;
#elif defined(__linux__) && defined(SYS_renameat2)
    constexpr unsigned int kRenameNoReplace = 1U;
    return syscall(SYS_renameat2, AT_FDCWD, source, AT_FDCWD, destination, kRenameNoReplace) == 0;
#else
    errno = ENOTSUP;
    return false;
#endif
#endif
}

string FileSystem::GetFullPath(const char* szPath) {
    if (NULL == szPath) {
        return string();
    }

    string strPath = szPath;
    if (!strPath.empty()) {
#ifdef _WIN32
        std::wstring widePath;
        if (Utf8ToWide(szPath, widePath)) {
            const DWORD count = GetFullPathNameW(widePath.c_str(), 0, nullptr, nullptr);
            if (count > 0) {
                std::vector<wchar_t> fullPath(static_cast<size_t>(count));
                if (GetFullPathNameW(widePath.c_str(), count, fullPath.data(), nullptr) != 0) {
                    WideToUtf8(fullPath.data(), strPath);
                }
            }
        }
        Utility::StringReplace(strPath, "/", "\\");
#else
        char path[PATH_MAX] = {0};
        if (NULL != realpath(szPath, path)) {
            strPath = path;
        }
        Utility::StringReplace(strPath, "//", "/");
#endif
    }
    return strPath;
}

string FileSystem::GetRealPathV(const char* szPath, ...) {
    FORMAT_V(szPath, szRealPath);
    return GetFullPath(szRealPath);
}

int64_t FileSystem::GetFileSize(FILE* fp) {
    if (NULL != fp) {
        _fseeki64(fp, 0, SEEK_END);
        int64_t size = _ftelli64(fp);
        _fseeki64(fp, 0, SEEK_SET);
        return (size > 0 ? size : 0);
    }
    return 0;
}

int64_t FileSystem::GetFileSize(const char* szPath) {
    int64_t size = 0;
    FILE* fp = NULL;
#ifdef _WIN32
    fp = OpenFileUtf8(szPath, L"rb");
#else
    _fopen64(fp, szPath, "rb");
#endif
    if (NULL != fp) {
        size = GetFileSize(fp);
        fclose(fp);
    }
    return size;
}

int64_t FileSystem::GetFileSizeV(const char* szPath, ...) {
    FORMAT_V(szPath, szFile);
    return GetFileSize(szFile);
}

string FileSystem::GetFileSizeString(const char* szFile) {
    return Utility::FormatSize(GetFileSize(szFile), 1024);
}

bool FileSystem::IsPathSuffix(const string& strPath, const char* suffix) {
    size_t nPos = strPath.rfind(suffix);
    if (string::npos != nPos) {
        if (nPos == (strPath.size() - strlen(suffix))) {
            return true;
        }
    }
    return false;
}

const char* FileSystem::GetTempFolder() {
    static once_flag s_flag;
    static string s_strTempFolder;
    if (s_strTempFolder.empty()) {
        call_once(s_flag, [&]() {
#ifdef _WIN32
            wchar_t szTempPath[PATH_MAX] = {0};
            if (0 != ::GetTempPathW(PATH_MAX, szTempPath)) {
                WideToUtf8(szTempPath, s_strTempFolder);
            } else {
                s_strTempFolder = GetFullPath("./");
            }
            if (!s_strTempFolder.empty() && s_strTempFolder.back() == '\\') {
                s_strTempFolder.pop_back();
            }
#else
			s_strTempFolder = "/tmp";
#endif
        });
    }
    return s_strTempFolder.c_str();
}

bool FileSystem::EnumFolder(const char* szFolder, bool bRecursive, enum_folder_callback filter,
                            enum_folder_callback callback) {
    string strFolder = szFolder == nullptr ? "" : szFolder;
    if (strFolder.empty() || NULL == callback) {
        return false;
    }

#ifdef _WIN32
    string strFromFolder = strFolder + "\\*";
    std::wstring widePattern;
    if (!Utf8ToWide(strFromFolder.c_str(), widePattern)) {
        return false;
    }
    WIN32_FIND_DATAW fd = {0};
    HANDLE hFind = ::FindFirstFileW(widePattern.c_str(), &fd);
    if (INVALID_HANDLE_VALUE == hFind) {
        return false;
    }

    do {
        if (0 == wcscmp(fd.cFileName, L".") || 0 == wcscmp(fd.cFileName, L"..")) {
            continue;
        }

        string strName;
        if (!WideToUtf8(fd.cFileName, strName)) {
            ::FindClose(hFind);
            return false;
        }
        string strPath = strFolder + "\\" + strName;
        const bool reparsePoint = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        bool bFolder = !reparsePoint && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        if (NULL != filter) {
            if (filter(bFolder, strPath)) {
                continue;
            }
        }

        if (callback(bFolder, strPath)) {
            ::FindClose(hFind);
            return false;
        }

        if (bFolder && bRecursive) {
            if (!EnumFolder(strPath.c_str(), bRecursive, filter, callback)) {
                ::FindClose(hFind);
                return false;
            }
        }
    } while (::FindNextFileW(hFind, &fd));
    const DWORD findError = ::GetLastError();
    ::FindClose(hFind);
    if (findError != ERROR_NO_MORE_FILES) {
        return false;
    }

#else

    DIR* dir = opendir(szFolder);
    if (NULL == dir) {
        return false;
    }

    errno = 0;
    dirent* ptr = readdir(dir);
    while (NULL != ptr) {
        if (0 == strcmp(ptr->d_name, ".") || 0 == strcmp(ptr->d_name, "..")) {
            errno = 0;
            ptr = readdir(dir);
            continue;
        }

        string strPath = strFolder + "/" + ptr->d_name;

        struct stat st{};
        if (lstat(strPath.c_str(), &st) != 0) {
            closedir(dir);
            return false;
        }
        const bool bFolder = S_ISDIR(st.st_mode);

        if (NULL != filter) {
            if (filter(bFolder, strPath)) {
                errno = 0;
                ptr = readdir(dir);
                continue;
            }
        }

        if (callback(bFolder, strPath)) {
            closedir(dir);
            return false;
        }

        if (bFolder && bRecursive) {
            if (!EnumFolder(strPath.c_str(), bRecursive, filter, callback)) {
                closedir(dir);
                return false;
            }
        }

        errno = 0;
        ptr = readdir(dir);
    }
    const int readError = errno;
    closedir(dir);
    if (readError != 0) {
        return false;
    }

#endif

    return true;
}

bool FileSystem::PathRemoveFileSpec(string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos) {
        path = path.substr(0, pos);
        return true;
    }
    return false;
}
