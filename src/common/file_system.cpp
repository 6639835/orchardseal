#include "file_system.h"

#include <limits>

#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

map<void*, void*> FileSystem::s_mapFiles;

bool FileSystem::IsRegularFile(const char* path) {
    struct stat st = {0};
    return 0 == stat(path, &st) && S_ISREG(st.st_mode);
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
    HANDLE file = ::CreateFileA(path, access, sharing, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
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
    const int descriptor = open(path, readOnly ? O_RDONLY : O_RDWR);
    if (descriptor < 0) {
        return nullptr;
    }

    struct stat fileStatus{};
    if (fstat(descriptor, &fileStatus) != 0 || fileStatus.st_size < 0 ||
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
    _fopen64(fp, szFile, "wb");
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
    _fopen64(fp, szFile, "rb");
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
    _fopen64(fp, szFile, "ab+");
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
    return ::PathIsDirectoryA(szFolder);
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
    string strPath = GetFullPath(szFolder);
    if (!IsFolder(strPath.c_str())) {
#ifdef _WIN32
        int32_t nRet = ::SHCreateDirectoryExA(NULL, strPath.c_str(), NULL);
        if (ERROR_SUCCESS != nRet && ERROR_ALREADY_EXISTS != nRet) {
            return false;
        }
#else
        size_t pos = 0;
        pos = strPath.find('/', pos);
        while (string::npos != pos) {
            string strFolder = strPath.substr(0, pos++);
            if (!strFolder.empty()) {
                if (0 != mkdir(strFolder.c_str(), 0755)) {
                    if (EEXIST != errno) {
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
        }
        return true;
#endif
    }
    return true;
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

    if (!IsFolder(szFolder)) {
        RemoveFile(szFolder);
        return true;
    }
#ifdef _WIN32
    string strFolder = szFolder;
    strFolder.push_back('\0');

    SHFILEOPSTRUCTA shfs;
    memset(&shfs, 0, sizeof(shfs));
    shfs.wFunc = FO_DELETE;
    shfs.pFrom = strFolder.c_str();
    shfs.fFlags = FOF_NOCONFIRMATION;
    shfs.fFlags |= (FOF_SILENT | FOF_NOERRORUI);
    return (0 == ::SHFileOperationA(&shfs));
#else
    return (0 == nftw(szFolder, RemoveFolderCallBack, 64, FTW_DEPTH | FTW_PHYS));
#endif
}

bool FileSystem::RemoveFolderV(const char* szPath, ...) {
    FORMAT_V(szPath, szFolder);
    return RemoveFolder(szFolder);
}

bool FileSystem::RemoveFile(const char* szFile) {
    return (NULL != szFile && 0 == remove(szFile));
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
    return ::PathFileExistsA(szFile);
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
        _fopen64(fp, szFile, "rb");
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
    return ::CopyFileA(szSrcFile, szDestFile, FALSE) ? true : false;
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

string FileSystem::GetFullPath(const char* szPath) {
    if (NULL == szPath) {
        return string();
    }

    string strPath = szPath;
    if (!strPath.empty()) {
#ifdef _WIN32
        char path[PATH_MAX] = {0};
        if (NULL != _fullpath(path, szPath, PATH_MAX)) {
            strPath = path;
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
    _fopen64(fp, szPath, "rb");
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
            char szTempPath[PATH_MAX] = {0};
            if (0 != ::GetTempPathA(PATH_MAX, szTempPath)) {
                s_strTempFolder = szTempPath;
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
    string strFolder = szFolder;
    if (strFolder.empty() || NULL == callback) {
        return false;
    }

#ifdef _WIN32
    string strFromFolder = strFolder + "\\*";
    WIN32_FIND_DATAA fd = {0};
    HANDLE hFind = ::FindFirstFileA(strFromFolder.c_str(), &fd);
    if (INVALID_HANDLE_VALUE == hFind) {
        return false;
    }

    do {
        if (0 == strcmp(fd.cFileName, ".") || 0 == strcmp(fd.cFileName, "..")) {
            continue;
        }

        string strName = fd.cFileName;
        string strPath = strFolder + "\\" + strName;
        bool bFolder = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

        if (NULL != filter) {
            if (filter(bFolder, strPath)) {
                continue;
            }
        }

        if (callback(bFolder, strPath)) {
            break;
        }

        if (bFolder && bRecursive) {
            EnumFolder(strPath.c_str(), bRecursive, filter, callback);
        }
    } while (::FindNextFileA(hFind, &fd));
    ::FindClose(hFind);

#else

    DIR* dir = opendir(szFolder);
    if (NULL == dir) {
        return false;
    }

    dirent* ptr = readdir(dir);
    while (NULL != ptr) {
        if (0 == strcmp(ptr->d_name, ".") || 0 == strcmp(ptr->d_name, "..")) {
            ptr = readdir(dir);
            continue;
        }

        string strPath = strFolder + "/" + ptr->d_name;

        bool bFolder = false;
        if (DT_DIR == ptr->d_type) {
            bFolder = true;
        } else if (DT_UNKNOWN == ptr->d_type) {
            struct stat st = {0};
            if (0 == stat(strPath.c_str(), &st) && S_ISDIR(st.st_mode)) {
                bFolder = true;
            }
        }

        if (NULL != filter) {
            if (filter(bFolder, strPath)) {
                ptr = readdir(dir);
                continue;
            }
        }

        if (callback(bFolder, strPath)) {
            break;
        }

        if (bFolder && bRecursive) {
            EnumFolder(strPath.c_str(), bRecursive, filter, callback);
        }

        ptr = readdir(dir);
    }
    closedir(dir);

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
