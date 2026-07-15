#include "hash.h"
#include "base64.h"
#include <openssl/sha.h>

bool Hash::SHA1(uint8_t* data, size_t size, string& strOutput) {
    strOutput.clear();
    uint8_t hash[20];
    ::SHA1(data, size, hash);
    strOutput.append((const char*)hash, 20);
    return true;
}

bool Hash::SHA256(uint8_t* data, size_t size, string& strOutput) {
    strOutput.clear();
    uint8_t hash[32];
    ::SHA256(data, size, hash);
    strOutput.append((const char*)hash, 32);
    return true;
}

bool Hash::SHA1(const string& strData, string& strOutput) {
    return Hash::SHA1((uint8_t*)strData.data(), strData.size(), strOutput);
}

bool Hash::SHA256(const string& strData, string& strOutput) {
    return Hash::SHA256((uint8_t*)strData.data(), strData.size(), strOutput);
}

bool Hash::SHA(const string& strData, string& strSHA1, string& strSHA256) {
    Hash::SHA1(strData, strSHA1);
    Hash::SHA256(strData, strSHA256);
    return (!strSHA1.empty() && !strSHA256.empty());
}

bool Hash::SHA1Text(const string& strData, string& strOutput) {
    string strSHASum;
    Hash::SHA1(strData, strSHASum);

    static const char hex_lower[] = "0123456789abcdef";
    strOutput.clear();
    strOutput.reserve(strSHASum.size() * 2);
    for (size_t i = 0; i < strSHASum.size(); i++) {
        uint8_t c = (uint8_t)strSHASum[i];
        strOutput += hex_lower[c >> 4];
        strOutput += hex_lower[c & 0x0F];
    }
    return (!strOutput.empty());
}

bool Hash::SHAFile(const char* szFile, string& strSHA1, string& strSHA256) {
    strSHA1.clear();
    strSHA256.clear();
    if (szFile == nullptr || *szFile == '\0') {
        return false;
    }
#ifdef _WIN32
    const int pathLength = static_cast<int>(strlen(szFile));
    const int wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szFile, pathLength, nullptr, 0);
    if (wideLength <= 0) {
        return false;
    }
    std::wstring widePath(static_cast<size_t>(wideLength), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, szFile, pathLength, widePath.data(), wideLength) !=
        wideLength) {
        return false;
    }
    HANDLE input = CreateFileW(widePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    BY_HANDLE_FILE_INFORMATION information{};
    if (input == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(input, &information) ||
        (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        if (input != INVALID_HANDLE_VALUE) {
            CloseHandle(input);
        }
        return false;
    }
#else
    const int input = open(szFile, O_RDONLY
#ifdef O_NOFOLLOW
                                       | O_NOFOLLOW
#endif
    );
    struct stat information{};
    if (input < 0 || fstat(input, &information) != 0 || !S_ISREG(information.st_mode)) {
        if (input >= 0) {
            close(input);
        }
        return false;
    }
#endif

    SHA_CTX sha1Context{};
    SHA256_CTX sha256Context{};
    if (::SHA1_Init(&sha1Context) != 1 || ::SHA256_Init(&sha256Context) != 1) {
#ifdef _WIN32
        CloseHandle(input);
#else
        close(input);
#endif
        return false;
    }

    bool success = true;
    uint8_t buffer[64U * 1024U];
    while (true) {
#ifdef _WIN32
        DWORD count = 0;
        if (!ReadFile(input, buffer, static_cast<DWORD>(sizeof(buffer)), &count, nullptr)) {
            success = false;
            break;
        }
#else
        ssize_t readResult;
        do {
            readResult = read(input, buffer, sizeof(buffer));
        } while (readResult < 0 && errno == EINTR);
        if (readResult < 0) {
            success = false;
            break;
        }
        const size_t count = static_cast<size_t>(readResult);
#endif
        if (count > 0 &&
            (::SHA1_Update(&sha1Context, buffer, count) != 1 || ::SHA256_Update(&sha256Context, buffer, count) != 1)) {
            success = false;
            break;
        }
        if (count == 0) {
            break;
        }
    }
#ifdef _WIN32
    if (!CloseHandle(input)) {
        success = false;
    }
#else
    if (close(input) != 0) {
        success = false;
    }
#endif

    uint8_t sha1[SHA_DIGEST_LENGTH];
    uint8_t sha256[SHA256_DIGEST_LENGTH];
    if (!success || ::SHA1_Final(sha1, &sha1Context) != 1 || ::SHA256_Final(sha256, &sha256Context) != 1) {
        return false;
    }
    strSHA1.assign(reinterpret_cast<const char*>(sha1), sizeof(sha1));
    strSHA256.assign(reinterpret_cast<const char*>(sha256), sizeof(sha256));
    return true;
}

bool Hash::SHABase64(const string& strData, string& strSHA1Base64, string& strSHA256Base64) {
    Base64Codec b64;
    string strSHA1;
    string strSHA256;
    SHA(strData, strSHA1, strSHA256);
    strSHA1Base64 = b64.Encode(strSHA1);
    strSHA256Base64 = b64.Encode(strSHA256);
    return (!strSHA1Base64.empty() && !strSHA256Base64.empty());
}

bool Hash::SHABase64File(const char* szFile, string& strSHA1Base64, string& strSHA256Base64) {
    Base64Codec b64;
    string strSHA1;
    string strSHA256;
    if (!SHAFile(szFile, strSHA1, strSHA256)) {
        strSHA1Base64.clear();
        strSHA256Base64.clear();
        return false;
    }
    strSHA1Base64 = b64.Encode(strSHA1);
    strSHA256Base64 = b64.Encode(strSHA256);
    return (!strSHA1Base64.empty() && !strSHA256Base64.empty());
}

void Hash::Print(const char* prefix, const uint8_t* hash, uint32_t size, const char* suffix) {
    Logger::PrintV("%s", prefix);
    for (uint32_t i = 0; i < size; i++) {
        Logger::PrintV("%02x", hash[i]);
    }
    Logger::PrintV("%s", suffix);
}

void Hash::Print(const char* prefix, const string& strSHASum, const char* suffix) {
    Print(prefix, (const uint8_t*)strSHASum.data(), (uint32_t)strSHASum.size(), suffix);
}

void Hash::PrintData1(const char* prefix, const string& strData, const char* suffix) {
    string strSHASum;
    Hash::SHA1(strData, strSHASum);
    Print(prefix, strSHASum, suffix);
}

void Hash::PrintData1(const char* prefix, uint8_t* data, size_t size, const char* suffix) {
    string strSHASum;
    Hash::SHA1(data, size, strSHASum);
    Print(prefix, strSHASum, suffix);
}

void Hash::PrintData256(const char* prefix, const string& strData, const char* suffix) {
    string strSHASum;
    Hash::SHA256(strData, strSHASum);
    Print(prefix, strSHASum, suffix);
}

void Hash::PrintData256(const char* prefix, uint8_t* data, size_t size, const char* suffix) {
    string strSHASum;
    Hash::SHA256(data, size, strSHASum);
    Print(prefix, strSHASum, suffix);
}
