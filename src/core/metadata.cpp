#include "metadata.h"
#include "json.h"
#include "hash.h"
#include "file_system.h"
#include "utility.h"
#include "zlib.h"

static uint32_t ReadBE32(const string& data, size_t off) {
    return ((uint32_t)(uint8_t)data[off] << 24) | ((uint32_t)(uint8_t)data[off + 1] << 16) |
           ((uint32_t)(uint8_t)data[off + 2] << 8) | ((uint32_t)(uint8_t)data[off + 3]);
}

static void AppendBE32(string& data, uint32_t value) {
    data.push_back((char)((value >> 24) & 0xff));
    data.push_back((char)((value >> 16) & 0xff));
    data.push_back((char)((value >> 8) & 0xff));
    data.push_back((char)(value & 0xff));
}

static void AppendPngChunk(string& png, const char type[4], const string& payload) {
    AppendBE32(png, (uint32_t)payload.size());
    size_t crcStart = png.size();
    png.append(type, 4);
    png.append(payload);
    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, (const Bytef*)png.data() + crcStart, (uInt)(png.size() - crcStart));
    AppendBE32(png, (uint32_t)crc);
}

static bool InflateData(const string& input, bool rawDeflate, string& output) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    int windowBits = rawDeflate ? -MAX_WBITS : MAX_WBITS;
    if (Z_OK != inflateInit2(&zs, windowBits)) {
        return false;
    }

    zs.next_in = (Bytef*)input.data();
    zs.avail_in = (uInt)input.size();
    char buffer[262144];
    int ret = Z_OK;
    while (ret == Z_OK) {
        zs.next_out = (Bytef*)buffer;
        zs.avail_out = sizeof(buffer);
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&zs);
            return false;
        }
        output.append(buffer, sizeof(buffer) - zs.avail_out);
    }

    inflateEnd(&zs);
    return (ret == Z_STREAM_END);
}

static bool DeflateData(const string& input, string& output) {
    uLongf outSize = compressBound((uLong)input.size());
    output.resize((size_t)outSize);
    int ret =
        compress2((Bytef*)&output[0], &outSize, (const Bytef*)input.data(), (uLong)input.size(), Z_BEST_COMPRESSION);
    if (Z_OK != ret) {
        output.clear();
        return false;
    }
    output.resize((size_t)outSize);
    return true;
}

static uint8_t PaethPredictor(uint8_t a, uint8_t b, uint8_t c) {
    int p = (int)a + (int)b - (int)c;
    int pa = abs(p - (int)a);
    int pb = abs(p - (int)b);
    int pc = abs(p - (int)c);
    if (pa <= pb && pa <= pc) {
        return a;
    }
    if (pb <= pc) {
        return b;
    }
    return c;
}

static bool DecodeApplePngRows(const string& filtered, uint32_t width, uint32_t height, string& normalizedRows) {
    const uint32_t bpp = 4;
    uint64_t rowBytes64 = (uint64_t)width * bpp;
    uint64_t expected64 = (rowBytes64 + 1) * height;
    if (0 == width || 0 == height || rowBytes64 > 0x7fffffff || filtered.size() < expected64) {
        return false;
    }

    size_t rowBytes = (size_t)rowBytes64;
    vector<uint8_t> prev(rowBytes, 0);
    vector<uint8_t> cur(rowBytes, 0);
    normalizedRows.clear();
    normalizedRows.reserve((rowBytes + 1) * height);

    const uint8_t* src = (const uint8_t*)filtered.data();
    for (uint32_t y = 0; y < height; y++) {
        uint8_t filter = *src++;
        for (size_t x = 0; x < rowBytes; x++) {
            uint8_t value = *src++;
            uint8_t left = (x >= bpp) ? cur[x - bpp] : 0;
            uint8_t up = prev[x];
            uint8_t upperLeft = (x >= bpp) ? prev[x - bpp] : 0;
            switch (filter) {
            case 0:
                break;
            case 1:
                value = (uint8_t)(value + left);
                break;
            case 2:
                value = (uint8_t)(value + up);
                break;
            case 3:
                value = (uint8_t)(value + (uint8_t)(((int)left + (int)up) / 2));
                break;
            case 4:
                value = (uint8_t)(value + PaethPredictor(left, up, upperLeft));
                break;
            default:
                return false;
            }
            cur[x] = value;
        }

        normalizedRows.push_back(0); // Store normalized output with no PNG filter.
        for (size_t x = 0; x < rowBytes; x += 4) {
            uint8_t b = cur[x + 0];
            uint8_t g = cur[x + 1];
            uint8_t r = cur[x + 2];
            uint8_t a = cur[x + 3];
            if (a > 0 && a < 255) {
                r = (uint8_t)std::min(255, ((int)r * 255 + a / 2) / a);
                g = (uint8_t)std::min(255, ((int)g * 255 + a / 2) / a);
                b = (uint8_t)std::min(255, ((int)b * 255 + a / 2) / a);
            }
            normalizedRows.push_back((char)r);
            normalizedRows.push_back((char)g);
            normalizedRows.push_back((char)b);
            normalizedRows.push_back((char)a);
        }
        prev.swap(cur);
    }

    return true;
}

static bool ConvertAppleOptimizedPng(const string& input, string& output) {
    static const char kPngSignature[] = "\x89PNG\r\n\x1a\n";
    if (input.size() < 8 || 0 != memcmp(input.data(), kPngSignature, 8)) {
        return false;
    }

    bool hasCgBI = false;
    string ihdr;
    string idat;
    uint32_t width = 0;
    uint32_t height = 0;
    uint8_t bitDepth = 0;
    uint8_t colorType = 0;
    uint8_t compression = 0;
    uint8_t filter = 0;
    uint8_t interlace = 0;

    size_t off = 8;
    while (off + 12 <= input.size()) {
        uint32_t len = ReadBE32(input, off);
        off += 4;
        if (off + 4 + len + 4 > input.size()) {
            return false;
        }
        string type(input.data() + off, 4);
        off += 4;
        string payload(input.data() + off, len);
        off += len + 4; // skip CRC too

        if ("CgBI" == type) {
            hasCgBI = true;
            continue;
        }
        if ("IHDR" == type) {
            if (payload.size() != 13) {
                return false;
            }
            ihdr = payload;
            width = ReadBE32(ihdr, 0);
            height = ReadBE32(ihdr, 4);
            bitDepth = (uint8_t)ihdr[8];
            colorType = (uint8_t)ihdr[9];
            compression = (uint8_t)ihdr[10];
            filter = (uint8_t)ihdr[11];
            interlace = (uint8_t)ihdr[12];
        } else if ("IDAT" == type) {
            idat += payload;
        } else if ("IEND" == type) {
            break;
        }
    }

    if (!hasCgBI || ihdr.empty() || idat.empty()) {
        return false;
    }
    if (bitDepth != 8 || colorType != 6 || compression != 0 || filter != 0 || interlace != 0) {
        Logger::WarnV(
            ">>> Metadata: unsupported CgBI PNG format, copying original icon. bitDepth=%u colorType=%u interlace=%u\n",
            bitDepth, colorType, interlace);
        return false;
    }

    string inflated;
    if (!InflateData(idat, true, inflated)) {
        // A few files contain a CgBI marker but use a normal zlib stream; accept those too.
        if (!InflateData(idat, false, inflated)) {
            return false;
        }
    }

    string normalizedRows;
    if (!DecodeApplePngRows(inflated, width, height, normalizedRows)) {
        return false;
    }

    string compressed;
    if (!DeflateData(normalizedRows, compressed)) {
        return false;
    }

    output.clear();
    output.append(kPngSignature, 8);
    AppendPngChunk(output, "IHDR", ihdr);
    AppendPngChunk(output, "IDAT", compressed);
    AppendPngChunk(output, "IEND", string());
    return true;
}

static bool CopyIconAsValidPng(const string& strSourceIcon, const string& strDestIcon) {
    string iconData;
    if (!FileSystem::ReadFile(strSourceIcon.c_str(), iconData)) {
        return false;
    }

    string converted;
    if (ConvertAppleOptimizedPng(iconData, converted)) {
        Logger::PrintV(">>> Metadata: converted Apple optimized icon PNG: %s\n", strSourceIcon.c_str());
        return FileSystem::WriteFile(strDestIcon.c_str(), converted);
    }

    return FileSystem::CopyFile(strSourceIcon.c_str(), strDestIcon.c_str());
}

static void AddIconName(vector<string>& arrNames, const string& strName) {
    if (!strName.empty() && arrNames.end() == find(arrNames.begin(), arrNames.end(), strName)) {
        arrNames.push_back(strName);
    }
}

static void GetIconNames(jvalue& jvInfo, vector<string>& arrNames) {
    if (jvInfo.has("CFBundleIcons")) {
        jvalue& jvIcons = jvInfo["CFBundleIcons"];
        if (jvIcons.has("CFBundlePrimaryIcon")) {
            jvalue& jvPrimary = jvIcons["CFBundlePrimaryIcon"];
            jvalue& jvFiles = jvPrimary["CFBundleIconFiles"];
            if (jvFiles.is_array()) {
                for (size_t i = 0; i < jvFiles.size(); i++) {
                    AddIconName(arrNames, jvFiles[i]);
                }
            }
        }
    }

    if (arrNames.empty() && jvInfo.has("CFBundleIconFiles")) {
        jvalue& jvIconFiles = jvInfo["CFBundleIconFiles"];
        if (jvIconFiles.is_array()) {
            for (size_t i = 0; i < jvIconFiles.size(); i++) {
                AddIconName(arrNames, jvIconFiles[i]);
            }
        }
    }

    if (arrNames.empty()) {
        AddIconName(arrNames, jvInfo["CFBundleIconFile"]);
    }
}

static bool FindLargestIcon(const string& strAppFolder, const vector<string>& arrIconNames, string& strBestPath) {
    int64_t nBestSize = 0;
    FileSystem::EnumFolder(strAppFolder.c_str(), false, NULL, [&](bool bFolder, const string& strPath) {
        if (bFolder) {
            return false;
        }
        string strBaseName = Utility::GetBaseName(strPath.c_str());
        for (const string& strPrefix : arrIconNames) {
            if (0 == strncmp(strBaseName.c_str(), strPrefix.c_str(), strPrefix.size())) {
                int64_t nSize = FileSystem::GetFileSize(strPath.c_str());
                if (nSize > nBestSize) {
                    nBestSize = nSize;
                    strBestPath = strPath;
                }
                break;
            }
        }
        return false;
    });
    return (nBestSize > 0);
}

bool GetMetadata(const string& strAppFolder, const string& strOutputDir, const string& strIpaFile) {
    string strInfoPlistData;
    string strInfoPlistPath = strAppFolder + "/Info.plist";
    if (!FileSystem::ReadFile(strInfoPlistPath.c_str(), strInfoPlistData)) {
        return Logger::ErrorV(">>> GetMetadata: Can't read %s\n", strInfoPlistPath.c_str());
    }

    jvalue jvInfo;
    jvInfo.read_plist(strInfoPlistData);

    string strAppName = jvInfo["CFBundleDisplayName"];
    if (strAppName.empty()) {
        strAppName = jvInfo["CFBundleName"].as_cstr();
    }

    string strAppVersion = jvInfo["CFBundleShortVersionString"];
    if (strAppVersion.empty()) {
        strAppVersion = jvInfo["CFBundleVersion"].as_cstr();
    }

    string strBundleId = jvInfo["CFBundleIdentifier"];

    // extract icon
    string strIconName;
    vector<string> arrIconNames;
    GetIconNames(jvInfo, arrIconNames);

    string strBestIconPath;
    if (!arrIconNames.empty() && FindLargestIcon(strAppFolder, arrIconNames, strBestIconPath)) {
        string strHash;
        Hash::SHA1Text(strBestIconPath, strHash);
        strIconName = strHash + ".png";
        if (!CopyIconAsValidPng(strBestIconPath, strOutputDir + "/" + strIconName)) {
            strIconName.clear();
            Logger::WarnV(">>> Metadata: failed to export icon: %s\n", strBestIconPath.c_str());
        }
    }

    // ipa file info
    int64_t nIpaSize = 0;
    string strFileName;
    if (!strIpaFile.empty()) {
        nIpaSize = FileSystem::GetFileSize(strIpaFile.c_str());
        strFileName = Utility::GetBaseName(strIpaFile.c_str());
    }

    // write json
    jvalue jvMeta;
    jvMeta["AppName"] = strAppName;
    jvMeta["AppVersion"] = strAppVersion;
    jvMeta["AppBundleIdentifier"] = strBundleId;
    jvMeta["AppSize"] = (int)nIpaSize;
    jvMeta["IconName"] = strIconName.empty() ? "" : strIconName;
    jvMeta["FileName"] = strFileName;
    jvMeta["Timestamp"] = (int)Utility::GetUnixStamp();

    string strMetaPath = strOutputDir + "/metadata.json";
    if (!jvMeta.style_write_to_file("%s", strMetaPath.c_str())) {
        return Logger::ErrorV(">>> GetMetadata: Can't write %s\n", strMetaPath.c_str());
    }

    Logger::PrintV(">>> Metadata:\t%s\n", strMetaPath.c_str());
    return true;
}
