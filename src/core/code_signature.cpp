#include "common.h"
#include "json.h"
#include "mach-o.h"
#include "signing_asset.h"
#include "code_signature.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <cstddef>
#include <openssl/sha.h>

namespace {
    constexpr uint32_t kMaximumCodeSignatureBlobCount = 64;
    std::size_t CodeDirectoryHeaderSize(std::uint32_t version) {
        if (version >= 0x20400)
            return sizeof(CS_CodeDirectory);
        if (version >= 0x20300)
            return offsetof(CS_CodeDirectory, execSegBase);
        if (version >= 0x20200)
            return offsetof(CS_CodeDirectory, spare3);
        if (version >= 0x20100)
            return offsetof(CS_CodeDirectory, teamOffset);
        return offsetof(CS_CodeDirectory, scatterOffset);
    }
} // namespace

void CodeSignature::_DERLength(string& strBlob, uint64_t uLength) {
    if (uLength < 128) {
        strBlob.append(1, (char)uLength);
    } else {
        uint32_t sLength = (64 - Utility::builtin_clzll(uLength) + 7) / 8;
        strBlob.append(1, (char)(0x80 | sLength));
        sLength *= 8;
        do {
            strBlob.append(1, (char)(uLength >> (sLength -= 8)));
        } while (sLength != 0);
    }
}

string CodeSignature::_DER(const jvalue& data) {
    string output;
    if (!_DERChecked(data, output))
        output.clear();
    return output;
}

bool CodeSignature::_DERChecked(const jvalue& data, string& strOutput) {
    strOutput.clear();
    if (data.is_bool()) {
        strOutput.append(1, 0x01);
        strOutput.append(1, 1);
        strOutput.append(1, data.as_bool() ? (char)0xff : (char)0x00);
    } else if (data.is_int()) {
        const int64_t value = data.as_int64();
        uint64_t bits = static_cast<uint64_t>(value);
        unsigned byteCount = sizeof(bits);
        while (byteCount > 1) {
            const uint8_t leading = static_cast<uint8_t>(bits >> ((byteCount - 1) * 8));
            const uint8_t next = static_cast<uint8_t>(bits >> ((byteCount - 2) * 8));
            if ((leading == 0x00 && (next & 0x80) == 0) || (leading == 0xff && (next & 0x80) != 0)) {
                --byteCount;
            } else {
                break;
            }
        }
        strOutput.append(1, 0x02);
        _DERLength(strOutput, byteCount);
        for (unsigned byte = byteCount; byte > 0; --byte) {
            strOutput.append(1, static_cast<char>(bits >> ((byte - 1) * 8)));
        }
    } else if (data.is_string()) {
        string strVal = data.as_cstr();
        strOutput.append(1, 0x0c);
        _DERLength(strOutput, strVal.size());
        strOutput += strVal;
    } else if (data.is_array()) {
        string strArray;
        size_t size = data.size();
        for (size_t i = 0; i < size; i++) {
            string item;
            if (!_DERChecked(data[i], item) || item.size() > std::numeric_limits<uint32_t>::max() - strArray.size())
                return false;
            strArray += item;
        }
        strOutput.append(1, 0x30);
        _DERLength(strOutput, strArray.size());
        strOutput += strArray;
    } else if (data.is_object()) {
        vector<string> arrKeys;
        data.get_keys(arrKeys);
        std::sort(arrKeys.begin(), arrKeys.end());

        string strDict;
        for (size_t i = 0; i < arrKeys.size(); i++) {
            string& strKey = arrKeys[i];
            string strVal;
            if (!_DERChecked(data[strKey], strVal))
                return false;

            string strEntry;
            strEntry.append(1, 0x0c);
            _DERLength(strEntry, strKey.size());
            strEntry += strKey;
            strEntry += strVal;

            strDict.append(1, 0x30);
            _DERLength(strDict, strEntry.size());
            if (strEntry.size() > std::numeric_limits<uint32_t>::max() - strDict.size())
                return false;
            strDict += strEntry;
        }

        strOutput.append(1, (char)0xb0);
        _DERLength(strOutput, strDict.size());
        strOutput += strDict;
    } else {
        return false;
    }
    return strOutput.size() <= std::numeric_limits<uint32_t>::max();
}

uint32_t CodeSignature::SlotParseGeneralHeader(const char* szSlotName, uint8_t* pSlotBase, CS_BlobIndex* pbi) {
    uint32_t magic = 0;
    uint32_t encodedLength = 0;
    std::memcpy(&magic, pSlotBase, sizeof(magic));
    std::memcpy(&encodedLength, pSlotBase + sizeof(magic), sizeof(encodedLength));
    const uint32_t uSlotLength = LE(encodedLength);
    Logger::PrintV("\n  > %s: \n", szSlotName);
    Logger::PrintV("\ttype: \t\t0x%x\n", LE(pbi->type));
    Logger::PrintV("\toffset: \t%u\n", LE(pbi->offset));
    Logger::PrintV("\tmagic: \t\t0x%x\n", LE(magic));
    Logger::PrintV("\tlength: \t%u\n", uSlotLength);
    return uSlotLength;
}

void CodeSignature::SlotParseGeneralTailer(uint8_t* pSlotBase, uint32_t uSlotLength) {
    Hash::PrintData1("\tSHA-1:  \t", pSlotBase, uSlotLength);
    Hash::PrintData256("\tSHA-256:\t", pSlotBase, uSlotLength);
}

bool CodeSignature::SlotParseRequirements(uint8_t* pSlotBase, CS_BlobIndex* pbi) {
    uint32_t uSlotLength = SlotParseGeneralHeader("CSSLOT_REQUIREMENTS", pSlotBase, pbi);
    if (uSlotLength < 8) {
        return false;
    }

#ifndef _WIN32
    if (FileSystem::IsFileExists("/usr/bin/csreq")) {
        char temporaryPath[] = "/tmp/orchardseal-requirements-XXXXXX";
        const int descriptor = mkstemp(temporaryPath);
        bool writtenSuccessfully = descriptor >= 0;
        size_t written = 0;
        while (writtenSuccessfully && written < uSlotLength) {
            const ssize_t result = write(descriptor, pSlotBase + written, uSlotLength - written);
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0) {
                writtenSuccessfully = false;
                break;
            }
            written += static_cast<size_t>(result);
        }
        if (descriptor >= 0 && close(descriptor) != 0)
            writtenSuccessfully = false;
        if (writtenSuccessfully) {
            const string command = string("/usr/bin/csreq -r ") + temporaryPath + " -t";
            char result[1024] = {0};
            FILE* process = popen(command.c_str(), "r");
            if (process != nullptr) {
                while (fgets(result, sizeof(result), process) != nullptr) {
                    Logger::PrintV("\treqtext: \t%s", result);
                }
                pclose(process);
            }
        }
        if (descriptor >= 0)
            unlink(temporaryPath);
    }
#endif

    SlotParseGeneralTailer(pSlotBase, uSlotLength);

    if (Logger::IsDebug()) {
        FileSystem::WriteFile("./.orchardseal_debug/Requirements.slot", (const char*)pSlotBase, uSlotLength);
    }
    return true;
}

bool CodeSignature::SlotBuildRequirements(const string& strBundleID, const string& strSubjectCN, string& strOutput) {
    strOutput.clear();

    // Empty requirement set (ldid-style: magic + length=12 + count=0)
    if (strBundleID.empty() || strSubjectCN.empty()) {
        uint32_t magic = BE((uint32_t)CSMAGIC_REQUIREMENTS);
        uint32_t length = BE((uint32_t)12);
        uint32_t count = 0;
        strOutput.append((const char*)&magic, 4);
        strOutput.append((const char*)&length, 4);
        strOutput.append((const char*)&count, 4);
        return true;
    }

    // Helper: append a uint32 in big-endian
    auto appendBE32 = [&strOutput](uint32_t val) {
        uint32_t be = BE(val);
        strOutput.append((const char*)&be, 4);
    };

    // Apple WWDR intermediate marker OID: 1.2.840.113635.100.6.2.1
    static const uint8_t kAppleWWDROID[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01};

    // ── Build the inner requirement expression blob (CSMAGIC_REQUIREMENT) ──
    // Generates the designated requirement equivalent to:
    //   identifier "<bundleID>" and anchor apple generic
    //     and certificate leaf[subject.CN] = "<subjectCN>"
    //     and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */
    string strExpr;
    auto appendExprBE32 = [&strExpr](uint32_t val) {
        uint32_t be = BE(val);
        strExpr.append((const char*)&be, 4);
    };

    // exprForm = 1 (expression follows)
    appendExprBE32(kReqOpTrue);

    // opAnd( opIdent(bundleID), opAnd( opAppleGenericAnchor, opAnd( opCertField(leaf, "subject.CN", matchEqual,
    // subjectCN), opCertGeneric(1, wwdrOID, matchExists) ) ) )

    // opAnd #1
    appendExprBE32(kReqOpAnd);
    // opIdent + bundleID
    appendExprBE32(kReqOpIdent);
    { // padded bundleID
        uint32_t len = BE((uint32_t)strBundleID.size());
        strExpr.append((const char*)&len, 4);
        strExpr.append(strBundleID.data(), strBundleID.size());
        size_t pad = (4 - (strBundleID.size() % 4)) % 4;
        if (pad > 0)
            strExpr.append(pad, '\0');
    }

    // opAnd #2
    appendExprBE32(kReqOpAnd);
    // opAppleGenericAnchor
    appendExprBE32(kReqOpAppleGenericAnchor);

    // opAnd #3
    appendExprBE32(kReqOpAnd);
    // opCertField: certificate leaf[subject.CN] = "<subjectCN>"
    appendExprBE32(kReqOpCertField);
    appendExprBE32(0); // slot 0 = leaf certificate
    {                  // "subject.CN" padded
        const char kSubjectCN[] = "subject.CN";
        uint32_t len = BE((uint32_t)(sizeof(kSubjectCN) - 1));
        strExpr.append((const char*)&len, 4);
        strExpr.append(kSubjectCN, sizeof(kSubjectCN) - 1);
        size_t pad = (4 - ((sizeof(kSubjectCN) - 1) % 4)) % 4;
        if (pad > 0)
            strExpr.append(pad, '\0');
    }
    appendExprBE32(kReqMatchEqual);
    { // padded subjectCN
        uint32_t len = BE((uint32_t)strSubjectCN.size());
        strExpr.append((const char*)&len, 4);
        strExpr.append(strSubjectCN.data(), strSubjectCN.size());
        size_t pad = (4 - (strSubjectCN.size() % 4)) % 4;
        if (pad > 0)
            strExpr.append(pad, '\0');
    }

    // opCertGeneric: certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */
    appendExprBE32(kReqOpCertGeneric);
    appendExprBE32(1); // slot 1 = intermediate certificate
    {                  // WWDR OID padded
        uint32_t len = BE((uint32_t)sizeof(kAppleWWDROID));
        strExpr.append((const char*)&len, 4);
        strExpr.append((const char*)kAppleWWDROID, sizeof(kAppleWWDROID));
        size_t pad = (4 - (sizeof(kAppleWWDROID) % 4)) % 4;
        if (pad > 0)
            strExpr.append(pad, '\0');
    }
    appendExprBE32(kReqMatchExists);

    // ── Build the outer requirements vector (CSMAGIC_REQUIREMENTS) ──
    // Outer header: magic(4) + length(4) + count(4) + BlobIndex[type(4) + offset(4)] = 20 bytes
    uint32_t reqBlobLen = 8 + (uint32_t)strExpr.size(); // inner magic + inner length + expr
    uint32_t outerHeaderLen = 20;
    uint32_t totalLen = outerHeaderLen + reqBlobLen;

    // Outer: CSMAGIC_REQUIREMENTS header
    appendBE32(CSMAGIC_REQUIREMENTS);
    appendBE32(totalLen);
    appendBE32(1);                             // count = 1
    appendBE32(kSecDesignatedRequirementType); // type = 3
    appendBE32(outerHeaderLen);                // offset to inner blob

    // Inner: CSMAGIC_REQUIREMENT blob
    appendBE32(CSMAGIC_REQUIREMENT);
    appendBE32(reqBlobLen);
    strOutput.append(strExpr.data(), strExpr.size());

    return true;
}

bool CodeSignature::SlotParseEntitlements(uint8_t* pSlotBase, CS_BlobIndex* pbi) {
    uint32_t uSlotLength = SlotParseGeneralHeader("CSSLOT_ENTITLEMENTS", pSlotBase, pbi);
    if (uSlotLength < 8) {
        return false;
    }

    string strEntitlements = "\t\t\t";
    strEntitlements.append((const char*)pSlotBase + 8, uSlotLength - 8);
    Utility::StringReplace(strEntitlements, "\n", "\n\t\t\t");
    Logger::PrintV("\tentitlements: \n%s\n", strEntitlements.c_str());

    SlotParseGeneralTailer(pSlotBase, uSlotLength);

    if (Logger::IsDebug()) {
        FileSystem::WriteFile("./.orchardseal_debug/Entitlements.slot", (const char*)pSlotBase, uSlotLength);
        FileSystem::WriteFile("./.orchardseal_debug/Entitlements.plist", (const char*)pSlotBase + 8, uSlotLength - 8);
    }
    return true;
}

bool CodeSignature::SlotParseDerEntitlements(uint8_t* pSlotBase, CS_BlobIndex* pbi) {
    uint32_t uSlotLength = SlotParseGeneralHeader("CSSLOT_DER_ENTITLEMENTS", pSlotBase, pbi);
    if (uSlotLength < 8) {
        return false;
    }

    SlotParseGeneralTailer(pSlotBase, uSlotLength);

    if (Logger::IsDebug()) {
        FileSystem::WriteFile("./.orchardseal_debug/Entitlements.der.slot", (const char*)pSlotBase, uSlotLength);
    }
    return true;
}

bool CodeSignature::SlotBuildEntitlements(const string& strEntitlements, string& strOutput) {
    strOutput.clear();
    if (strEntitlements.empty()) {
        return false;
    }

    if (strEntitlements.size() > std::numeric_limits<uint32_t>::max() - 8U)
        return false;
    uint32_t uMagic = BE((uint32_t)CSMAGIC_EMBEDDED_ENTITLEMENTS);
    uint32_t uLength = BE((uint32_t)strEntitlements.size() + 8);

    strOutput.append((const char*)&uMagic, sizeof(uMagic));
    strOutput.append((const char*)&uLength, sizeof(uLength));
    strOutput.append(strEntitlements.data(), strEntitlements.size());

    return true;
}

bool CodeSignature::SlotBuildDerEntitlements(const string& strEntitlements, string& strOutput) {
    strOutput.clear();
    if (strEntitlements.empty()) {
        return false;
    }

    jvalue jvInfo;
    if (!jvInfo.read_plist(strEntitlements))
        return false;

    string strInnerDict;
    if (!_DERChecked(jvInfo, strInnerDict))
        return false;

    string strVersion;
    strVersion.append(1, 0x02);
    strVersion.append(1, 0x01);
    strVersion.append(1, 0x01);

    string strBody = strVersion + strInnerDict;

    string strRawEntitlementsData;
    strRawEntitlementsData.append(1, (char)0x70);
    _DERLength(strRawEntitlementsData, strBody.size());
    strRawEntitlementsData += strBody;

    if (strRawEntitlementsData.size() > std::numeric_limits<uint32_t>::max() - 8U)
        return false;
    uint32_t uMagic = BE((uint32_t)CSMAGIC_EMBEDDED_DER_ENTITLEMENTS);
    uint32_t uLength = BE((uint32_t)strRawEntitlementsData.size() + 8);

    strOutput.append((const char*)&uMagic, sizeof(uMagic));
    strOutput.append((const char*)&uLength, sizeof(uLength));
    strOutput.append(strRawEntitlementsData.data(), strRawEntitlementsData.size());

    return true;
}

bool CodeSignature::SlotParseCodeDirectory(uint8_t* pSlotBase, CS_BlobIndex* pbi) {
    uint32_t uSlotLength = SlotParseGeneralHeader("CSSLOT_CODEDIRECTORY", pSlotBase, pbi);
    if (uSlotLength < 8) {
        return false;
    }

    CS_CodeDirectory cdHeader{};
    std::memcpy(&cdHeader, pSlotBase, std::min<std::size_t>(uSlotLength, sizeof(cdHeader)));
    uint8_t* pHashes = pSlotBase + LE(cdHeader.hashOffset);

    Logger::PrintV("\tversion: \t0x%x\n", LE(cdHeader.version));
    Logger::PrintV("\tflags: \t\t%u\n", LE(cdHeader.flags));
    Logger::PrintV("\thashOffset: \t%u\n", LE(cdHeader.hashOffset));
    Logger::PrintV("\tidentOffset: \t%u\n", LE(cdHeader.identOffset));
    Logger::PrintV("\tnSpecialSlots: \t%u\n", LE(cdHeader.nSpecialSlots));
    Logger::PrintV("\tnCodeSlots: \t%u\n", LE(cdHeader.nCodeSlots));
    Logger::PrintV("\tcodeLimit: \t%u\n", LE(cdHeader.codeLimit));
    Logger::PrintV("\thashSize: \t%u\n", cdHeader.hashSize);
    Logger::PrintV("\thashType: \t%u\n", cdHeader.hashType);
    Logger::PrintV("\tspare1: \t%u\n", cdHeader.spare1);
    Logger::PrintV("\tpageSize: \t%u\n", cdHeader.pageSize);
    Logger::PrintV("\tspare2: \t%u\n", LE(cdHeader.spare2));

    uint32_t uVersion = LE(cdHeader.version);
    if (uVersion >= 0x20100) {
        Logger::PrintV("\tscatterOffset: \t%u\n", LE(cdHeader.scatterOffset));
    }
    if (uVersion >= 0x20200) {
        Logger::PrintV("\tteamOffset: \t%u\n", LE(cdHeader.teamOffset));
    }
    if (uVersion >= 0x20300) {
        Logger::PrintV("\tspare3: \t%u\n", LE(cdHeader.spare3));
        Logger::PrintV("\tcodeLimit64: \t%llu\n", LE(cdHeader.codeLimit64));
    }
    if (uVersion >= 0x20400) {
        Logger::PrintV("\texecSegBase: \t%llu\n", LE(cdHeader.execSegBase));
        Logger::PrintV("\texecSegLimit: \t%llu\n", LE(cdHeader.execSegLimit));
        Logger::PrintV("\texecSegFlags: \t%llu\n", LE(cdHeader.execSegFlags));
    }

    Logger::PrintV("\tidentifier: \t%s\n", pSlotBase + LE(cdHeader.identOffset));
    if (uVersion >= 0x20200) {
        const uint32_t teamOffset = LE(cdHeader.teamOffset);
        Logger::PrintV("\tteamid: \t%s\n", teamOffset == 0 ? "" : reinterpret_cast<char*>(pSlotBase + teamOffset));
    }

    Logger::PrintV("\tSpecialSlots:\n");
    for (uint32_t remaining = LE(cdHeader.nSpecialSlots); remaining > 0; --remaining) {
        const uint32_t i = remaining - 1;
        const char* suffix = "\t\n";
        switch (i) {
        case 0:
            suffix = "\tInfo.plist\n";
            break;
        case 1:
            suffix = "\tRequirements Slot\n";
            break;
        case 2:
            suffix = "\tCodeResources\n";
            break;
        case 3:
            suffix = "\tApplication Specific\n";
            break;
        case 4:
            suffix = "\tEntitlements Slot\n";
            break;
        case 6:
            suffix = "\tEntitlements(DER) Slot\n";
            break;
        }
        Hash::Print("\t\t\t", pHashes - cdHeader.hashSize * (i + 1), cdHeader.hashSize, suffix);
    }

    if (Logger::IsDebug()) {
        Logger::Print("\tCodeSlots:\n");
        for (uint32_t i = 0; i < LE(cdHeader.nCodeSlots); i++) {
            Hash::Print("\t\t\t", pHashes + cdHeader.hashSize * i, cdHeader.hashSize);
        }
    } else {
        Logger::Print("\tCodeSlots: \tomitted. (use -d option for details)\n");
    }

    SlotParseGeneralTailer(pSlotBase, uSlotLength);

    if (Logger::IsDebug()) {
        if (1 == cdHeader.hashType) {
            FileSystem::WriteFile("./.orchardseal_debug/CodeDirectory_SHA1.slot", (const char*)pSlotBase, uSlotLength);
        } else if (2 == cdHeader.hashType) {
            FileSystem::WriteFile("./.orchardseal_debug/CodeDirectory_SHA256.slot", (const char*)pSlotBase,
                                  uSlotLength);
        }
    }

    return true;
}

bool CodeSignature::SlotBuildCodeDirectory(bool bAlternate, uint8_t* pCodeBase, uint32_t uCodeLength,
                                           uint8_t* pCodeSlotsData, uint32_t uCodeSlotsDataLength,
                                           uint64_t execSegLimit, uint64_t execSegFlags, const string& strBundleId,
                                           const string& strTeamId, const string& strInfoPlistSHA,
                                           const string& strRequirementsSlotSHA, const string& strCodeResourcesSHA,
                                           const string& strEntitlementsSlotSHA,
                                           const string& strDerEntitlementsSlotSHA, bool isExecuteArch, bool isAdhoc,
                                           string& strOutput) {
    strOutput.clear();
    if (NULL == pCodeBase || uCodeLength <= 0 || strBundleId.empty() || (strTeamId.empty() && !isAdhoc)) {
        return false;
    }

    uint32_t uVersion = 0x20400;

    CS_CodeDirectory cdHeader;
    memset(&cdHeader, 0, sizeof(cdHeader));
    cdHeader.magic = BE((uint32_t)CSMAGIC_CODEDIRECTORY);
    cdHeader.length = 0;
    cdHeader.version = BE(uVersion);
    cdHeader.flags = isAdhoc ? BE(static_cast<uint32_t>(CS_SEC_CODESIGNATURE_ADHOC)) : 0U;
    cdHeader.hashOffset = 0;
    cdHeader.identOffset = 0;
    cdHeader.nSpecialSlots = 0;
    cdHeader.nCodeSlots = 0;
    cdHeader.codeLimit = BE(uCodeLength);
    cdHeader.hashSize = bAlternate ? 32 : 20;
    cdHeader.hashType = bAlternate ? 2 : 1;
    cdHeader.spare1 = 0;
    cdHeader.pageSize = 12;
    cdHeader.spare2 = 0;
    cdHeader.scatterOffset = 0;
    cdHeader.teamOffset = 0;
    cdHeader.execSegBase = 0;
    cdHeader.execSegLimit = BE(execSegLimit);
    cdHeader.execSegFlags = BE(execSegFlags);

    string strEmptySHA;
    strEmptySHA.append(cdHeader.hashSize, 0);
    vector<string> arrSpecialSlots;

    if (isExecuteArch) {
        arrSpecialSlots.push_back(strDerEntitlementsSlotSHA.empty() ? strEmptySHA : strDerEntitlementsSlotSHA);
        arrSpecialSlots.push_back(strEmptySHA);
    }
    arrSpecialSlots.push_back(strEntitlementsSlotSHA.empty() ? strEmptySHA : strEntitlementsSlotSHA);
    arrSpecialSlots.push_back(strEmptySHA);
    arrSpecialSlots.push_back(strCodeResourcesSHA.empty() ? strEmptySHA : strCodeResourcesSHA);
    arrSpecialSlots.push_back(strRequirementsSlotSHA.empty() ? strEmptySHA : strRequirementsSlotSHA);
    arrSpecialSlots.push_back(strInfoPlistSHA.empty() ? strEmptySHA : strInfoPlistSHA);

    // Trailing entries whose hash == strEmptySHA in `arrSpecialSlots` can be omitted; erase them.
    // Special slots have negative indexes and come before code slots, i.e. index -1 is the 'Info.plist'
    // slot, and -2 is 'Requirements slot'.
    // Note that in `arrSpecialSlots` is reversed and trailing elements appear at front.
    auto itLastUsedSpecialSlot = std::find_if(arrSpecialSlots.begin(), arrSpecialSlots.end(),
                                              [&](const string& strSHA) { return strSHA != strEmptySHA; });
    if (itLastUsedSpecialSlot != arrSpecialSlots.begin()) {
        arrSpecialSlots.erase(arrSpecialSlots.begin(), itLastUsedSpecialSlot);
    }

    uint32_t uPageSize = 1u << cdHeader.pageSize;
    uint32_t uPages = uCodeLength / uPageSize;
    uint32_t uRemain = uCodeLength % uPageSize;
    uint32_t uCodeSlots = uPages + (uRemain > 0 ? 1 : 0);

    uint32_t uHeaderLength = 44;
    if (uVersion >= 0x20100) {
        uHeaderLength += sizeof(cdHeader.scatterOffset);
    }
    if (uVersion >= 0x20200) {
        uHeaderLength += sizeof(cdHeader.teamOffset);
    }
    if (uVersion >= 0x20300) {
        uHeaderLength += sizeof(cdHeader.spare3);
        uHeaderLength += sizeof(cdHeader.codeLimit64);
    }
    if (uVersion >= 0x20400) {
        uHeaderLength += sizeof(cdHeader.execSegBase);
        uHeaderLength += sizeof(cdHeader.execSegLimit);
        uHeaderLength += sizeof(cdHeader.execSegFlags);
    }

    uint32_t uBundleIDLength = (uint32_t)strBundleId.size() + 1;
    uint32_t uTeamIDLength = (uint32_t)strTeamId.size() + 1;
    uint32_t uSpecialSlotsLength = (uint32_t)arrSpecialSlots.size() * cdHeader.hashSize;
    uint32_t uCodeSlotsLength = uCodeSlots * cdHeader.hashSize;

    uint32_t uSlotLength = uHeaderLength + uBundleIDLength + uSpecialSlotsLength + uCodeSlotsLength;
    strOutput.reserve(uSlotLength + uTeamIDLength); // pre-allocate to avoid reallocations
    if (uVersion >= 0x20200 && !strTeamId.empty()) {
        uSlotLength += uTeamIDLength;
    }

    cdHeader.length = BE(uSlotLength);
    cdHeader.identOffset = BE(uHeaderLength);
    cdHeader.nSpecialSlots = BE((uint32_t)arrSpecialSlots.size());
    cdHeader.nCodeSlots = BE(uCodeSlots);

    uint32_t uHashOffset = uHeaderLength + uBundleIDLength + uSpecialSlotsLength;
    // `strTeamId` may be empty for ad-hoc signature; in that case, `cdHeader.teamOffset == 0` and string
    // data is not serialized below.
    if (uVersion >= 0x20200 && !strTeamId.empty()) {
        uHashOffset += uTeamIDLength;
        cdHeader.teamOffset = BE(uHeaderLength + uBundleIDLength);
    }
    cdHeader.hashOffset = BE(uHashOffset);

    strOutput.append((const char*)&cdHeader, uHeaderLength);
    strOutput.append(strBundleId.data(), strBundleId.size() + 1);
    if (uVersion >= 0x20200 && !strTeamId.empty()) {
        strOutput.append(strTeamId.data(), strTeamId.size() + 1);
    }

    for (uint32_t i = 0; i < LE(cdHeader.nSpecialSlots); i++) {
        strOutput.append(arrSpecialSlots[i].data(), arrSpecialSlots[i].size());
    }

    if (NULL != pCodeSlotsData && (uCodeSlotsDataLength == uCodeSlots * cdHeader.hashSize)) { // use exists
        strOutput.append((const char*)pCodeSlotsData, uCodeSlotsDataLength);
    } else {
        uint8_t hash[32]; // large enough for both SHA1 (20) and SHA256 (32)
        for (uint32_t i = 0; i < uPages; i++) {
            if (1 == cdHeader.hashType) {
                ::SHA1(pCodeBase + uPageSize * i, uPageSize, hash);
                strOutput.append((const char*)hash, 20);
            } else {
                ::SHA256(pCodeBase + uPageSize * i, uPageSize, hash);
                strOutput.append((const char*)hash, 32);
            }
        }
        if (uRemain > 0) {
            if (1 == cdHeader.hashType) {
                ::SHA1(pCodeBase + uPageSize * uPages, uRemain, hash);
                strOutput.append((const char*)hash, 20);
            } else {
                ::SHA256(pCodeBase + uPageSize * uPages, uRemain, hash);
                strOutput.append((const char*)hash, 32);
            }
        }
    }

    return true;
}

bool CodeSignature::SlotParseCMSSignature(uint8_t* pSlotBase, CS_BlobIndex* pbi) {
    uint32_t uSlotLength = SlotParseGeneralHeader("CSSLOT_SIGNATURESLOT", pSlotBase, pbi);
    if (uSlotLength < 8) {
        return false;
    }

    jvalue jvInfo;
    SigningAsset::GetCMSInfo(pSlotBase + 8, uSlotLength - 8, jvInfo);
    // Logger::PrintV("%s\n", jvInfo.styleWrite().c_str());

    Logger::Print("\tCertificates: \n");
    for (size_t i = 0; i < jvInfo["certs"].size(); i++) {
        Logger::PrintV("\t\t\t%s\t<=\t%s\n", jvInfo["certs"][i]["Subject"]["CN"].as_cstr(),
                       jvInfo["certs"][i]["Issuer"]["CN"].as_cstr());
    }

    Logger::Print("\tSignedAttrs: \n");
    if (jvInfo["attrs"].has("ContentType")) {
        Logger::PrintV("\t  ContentType: \t%s => %s\n", jvInfo["attrs"]["ContentType"]["obj"].as_cstr(),
                       jvInfo["attrs"]["ContentType"]["data"].as_cstr());
    }

    if (jvInfo["attrs"].has("SigningTime")) {
        Logger::PrintV("\t  SigningTime: \t%s => %s\n", jvInfo["attrs"]["SigningTime"]["obj"].as_cstr(),
                       jvInfo["attrs"]["SigningTime"]["data"].as_cstr());
    }

    if (jvInfo["attrs"].has("MessageDigest")) {
        Logger::PrintV("\t  MsgDigest: \t%s => %s\n", jvInfo["attrs"]["MessageDigest"]["obj"].as_cstr(),
                       jvInfo["attrs"]["MessageDigest"]["data"].as_cstr());
    }

    if (jvInfo["attrs"].has("CDHashes")) {
        string strData = jvInfo["attrs"]["CDHashes"]["data"].as_cstr();
        Utility::StringReplace(strData, "\n", "\n\t\t\t\t");
        Logger::PrintV("\t  CDHashes: \t%s => \n\t\t\t\t%s\n", jvInfo["attrs"]["CDHashes"]["obj"].as_cstr(),
                       strData.c_str());
    }

    if (jvInfo["attrs"].has("CDHashes2")) {
        Logger::PrintV("\t  CDHashes2: \t%s => \n", jvInfo["attrs"]["CDHashes2"]["obj"].as_cstr());
        for (size_t i = 0; i < jvInfo["attrs"]["CDHashes2"]["data"].size(); i++) {
            Logger::PrintV("\t\t\t\t%s\n", jvInfo["attrs"]["CDHashes2"]["data"][i].as_cstr());
        }
    }

    for (size_t i = 0; i < jvInfo["attrs"]["unknown"].size(); i++) {
        jvalue& jvAttr = jvInfo["attrs"]["unknown"][i];
        Logger::PrintV("\t  UnknownAttr: \t%s => %s, type: %d, count: %d\n", jvAttr["obj"].as_cstr(),
                       jvAttr["name"].as_cstr(), jvAttr["type"].as_int(), jvAttr["count"].as_int());
    }
    Logger::Print("\n");

    SlotParseGeneralTailer(pSlotBase, uSlotLength);

    if (Logger::IsDebug()) {
        FileSystem::WriteFile("./.orchardseal_debug/CMSSignature.slot", (const char*)pSlotBase, uSlotLength);
        FileSystem::WriteFile("./.orchardseal_debug/CMSSignature.der", (const char*)pSlotBase + 8, uSlotLength - 8);
    }
    return true;
}

bool CodeSignature::SlotBuildCMSSignature(SigningAsset* pSignAsset, const string& strCodeDirectorySlot,
                                          const string& strAltnateCodeDirectorySlot, string& strOutput) {
    strOutput.clear();
    if (pSignAsset->IsAdHoc()) { // The empty CSSLOT_SIGNATURESLOT
        uint8_t ldid[] = {0xfa, 0xde, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x08};
        strOutput.append((const char*)ldid, sizeof(ldid));
        return true;
    }

    // The CMS "cdhashes" plist (attr 1.2.840.113635.100.9.1) and the "CDHashes2"
    // attribute (1.2.840.113635.100.9.2) must only contain hashes of CodeDirectory
    // blobs that actually exist in the signature. When only one CodeDirectory is
    // serialized (SHA256-only mode), emitting hashes for a non-existent alternate
    // CD breaks Apple's code signature verification with errSecCSSignatureFailed
    // (`codesign --verify` reports "code or signature have been modified"):
    // verification computes hashes of the real CDs and finds the second entry
    // doesn't match any actual CD.
    //
    // Format rules derived from Apple codesign output:
    // - cdhashes plist: one entry per CD, value = first 20 bytes of the CD's
    //   "best" hash. For dual-hash builds (SHA1+SHA256) the primary CD uses SHA1
    //   directly (20 bytes) and the alternate uses SHA256 truncated to 20.
    //   For SHA256-only builds the single entry uses SHA256 truncated to 20.
    // - CDHashes2 attribute: full hash (32 bytes for SHA256) of each CD wrapped
    //   in `SEQUENCE { OID sha256, OCTET STRING hash }`. The current
    //   GenerateCMS() implementation consumes a single `strAltnateCodeDirectorySlot256`
    //   string for this attribute — when there is no alternate CD we pass the
    //   SHA256 of the primary CD instead of SHA256(empty).
    const bool bHasAlternate = !strAltnateCodeDirectorySlot.empty();

    jvalue jvHashes;
    string strCDHashesPlist;
    string strCodeDirectorySlotSHA1; // SHA1 of primary CD (used by CMS detached content & dual-hash plist[0])
    string strPrimaryCD_SHA256;      // SHA256 of primary CD (used in SHA256-only mode)
    string strAltnateCD_SHA256;      // SHA256 of alternate CD (dual-hash mode only)
    Hash::SHA1(strCodeDirectorySlot, strCodeDirectorySlotSHA1);
    Hash::SHA256(strCodeDirectorySlot, strPrimaryCD_SHA256);
    if (bHasAlternate) {
        Hash::SHA256(strAltnateCodeDirectorySlot, strAltnateCD_SHA256);
    }

    // 20-byte (truncated) hashes for the CDHashes plist.
    const size_t kPlistHashLen = 20;
    if (bHasAlternate) {
        jvHashes["cdhashes"][0].assign_data(strCodeDirectorySlotSHA1.data(), kPlistHashLen);
        jvHashes["cdhashes"][1].assign_data(strAltnateCD_SHA256.data(), kPlistHashLen);
    } else {
        // SHA256-only: single CD, use its SHA256 truncated to 20 bytes.
        jvHashes["cdhashes"][0].assign_data(strPrimaryCD_SHA256.data(), kPlistHashLen);
    }
    jvHashes.style_write_plist(strCDHashesPlist);

    // Full SHA256 hash to embed in the CDHashes2 signed attribute. In SHA256-only
    // mode this must be the SHA256 of the primary CD, not SHA256 of an empty
    // alternate — the latter is rejected by Apple's verifier.
    const string& strCDHashes2 = bHasAlternate ? strAltnateCD_SHA256 : strPrimaryCD_SHA256;

    string strCMSData;
    if (!pSignAsset->GenerateCMS(strCodeDirectorySlot, strCDHashesPlist, strCodeDirectorySlotSHA1, strCDHashes2,
                                 strCMSData)) {
        return false;
    }

    uint32_t uMagic = BE((uint32_t)CSMAGIC_BLOBWRAPPER);
    uint32_t uLength = BE((uint32_t)strCMSData.size() + 8);

    strOutput.append((const char*)&uMagic, sizeof(uMagic));
    strOutput.append((const char*)&uLength, sizeof(uLength));
    strOutput.append(strCMSData.data(), strCMSData.size());
    return true;
}

uint32_t CodeSignature::GetCodeSignatureLength(const uint8_t* pCSBase, uint32_t availableSize) {
    if (pCSBase != nullptr && availableSize >= sizeof(CS_SuperBlob)) {
        CS_SuperBlob header{};
        std::memcpy(&header, pCSBase, sizeof(header));
        const uint32_t length = LE(header.length);
        if (CSMAGIC_EMBEDDED_SIGNATURE == LE(header.magic) && length >= sizeof(header) && length <= availableSize) {
            return length;
        }
    }
    return 0;
}

bool CodeSignature::ParseCodeSignature(uint8_t* pCSBase, uint32_t availableSize) {
    const uint32_t totalLength = GetCodeSignatureLength(pCSBase, availableSize);
    if (totalLength == 0) {
        return false;
    }
    CS_SuperBlob superBlob{};
    std::memcpy(&superBlob, pCSBase, sizeof(superBlob));
    const uint32_t count = LE(superBlob.count);
    if (count > kMaximumCodeSignatureBlobCount || count > (totalLength - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex)) {
        return false;
    }

    Logger::PrintV("\n>>> CodeSignature Segment: \n");
    Logger::PrintV("\tmagic: \t\t0x%x\n", LE(superBlob.magic));
    Logger::PrintV("\tlength: \t%d\n", LE(superBlob.length));
    Logger::PrintV("\tslots: \t\t%d\n", count);

    const uint32_t indexEnd = static_cast<uint32_t>(sizeof(CS_SuperBlob) + count * sizeof(CS_BlobIndex));
    vector<std::pair<uint32_t, uint32_t>> slotRanges;
    slotRanges.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        CS_BlobIndex blobIndex{};
        std::memcpy(&blobIndex, pCSBase + sizeof(CS_SuperBlob) + i * sizeof(CS_BlobIndex), sizeof(blobIndex));
        CS_BlobIndex* pbi = &blobIndex;
        const uint32_t type = LE(blobIndex.type);
        const uint32_t slotOffset = LE(blobIndex.offset);
        if (slotOffset < indexEnd || slotOffset > totalLength || totalLength - slotOffset < 8) {
            return false;
        }
        uint8_t* pSlotBase = pCSBase + slotOffset;
        uint32_t slotLengthBE = 0;
        std::memcpy(&slotLengthBE, pSlotBase + 4, sizeof(slotLengthBE));
        const uint32_t slotLength = LE(slotLengthBE);
        if (slotLength < 8 || slotLength > totalLength - slotOffset) {
            return false;
        }
        slotRanges.emplace_back(slotOffset, slotLength);
        if (type == CSSLOT_CODEDIRECTORY || type == CSSLOT_ALTERNATE_CODEDIRECTORIES) {
            if (slotLength < offsetof(CS_CodeDirectory, scatterOffset)) {
                return false;
            }
            CS_CodeDirectory cd{};
            std::memcpy(&cd, pSlotBase, std::min<std::size_t>(slotLength, sizeof(cd)));
            const std::size_t requiredHeader = CodeDirectoryHeaderSize(LE(cd.version));
            if (slotLength < requiredHeader)
                return false;
            const uint32_t hashOffset = LE(cd.hashOffset);
            const uint32_t identOffset = LE(cd.identOffset);
            const uint32_t teamOffset = LE(cd.teamOffset);
            const uint64_t codeHashBytes = static_cast<uint64_t>(LE(cd.nCodeSlots)) * cd.hashSize;
            const uint64_t specialHashBytes = static_cast<uint64_t>(LE(cd.nSpecialSlots)) * cd.hashSize;
            if (cd.hashSize == 0 || hashOffset < requiredHeader || specialHashBytes > hashOffset - requiredHeader ||
                hashOffset > slotLength || codeHashBytes > slotLength - hashOffset || identOffset < requiredHeader ||
                identOffset >= slotLength ||
                std::memchr(pSlotBase + identOffset, 0, slotLength - identOffset) == nullptr ||
                (LE(cd.version) >= 0x20200 && teamOffset != 0 &&
                 (teamOffset < requiredHeader || teamOffset >= slotLength ||
                  std::memchr(pSlotBase + teamOffset, 0, slotLength - teamOffset) == nullptr))) {
                return false;
            }
        }
        switch (type) {
        case CSSLOT_CODEDIRECTORY:
            SlotParseCodeDirectory(pSlotBase, pbi);
            break;
        case CSSLOT_REQUIREMENTS:
            SlotParseRequirements(pSlotBase, pbi);
            break;
        case CSSLOT_ENTITLEMENTS:
            SlotParseEntitlements(pSlotBase, pbi);
            break;
        case CSSLOT_DER_ENTITLEMENTS:
            SlotParseDerEntitlements(pSlotBase, pbi);
            break;
        case CSSLOT_ALTERNATE_CODEDIRECTORIES:
            SlotParseCodeDirectory(pSlotBase, pbi);
            break;
        case CSSLOT_SIGNATURESLOT:
            SlotParseCMSSignature(pSlotBase, pbi);
            break;
        case CSSLOT_IDENTIFICATIONSLOT:
            SlotParseGeneralHeader("CSSLOT_IDENTIFICATIONSLOT", pSlotBase, pbi);
            break;
        case CSSLOT_TICKETSLOT:
            SlotParseGeneralHeader("CSSLOT_TICKETSLOT", pSlotBase, pbi);
            break;
        default:
            SlotParseGeneralTailer(pSlotBase, SlotParseGeneralHeader("CSSLOT_UNKNOWN", pSlotBase, pbi));
            break;
        }
    }

    std::sort(slotRanges.begin(), slotRanges.end());
    for (size_t index = 1; index < slotRanges.size(); ++index) {
        if (static_cast<uint64_t>(slotRanges[index - 1].first) + slotRanges[index - 1].second > slotRanges[index].first)
            return false;
    }

    if (Logger::IsDebug()) {
        FileSystem::WriteFile("./.orchardseal_debug/CodeSignature.blob", (const char*)pCSBase, totalLength);
    }
    return true;
}

bool CodeSignature::GetCodeSignatureExistsCodeSlotsData(uint8_t* pCSBase, uint32_t signatureSize,
                                                        uint8_t*& pCodeSlots1Data, uint32_t& uCodeSlots1DataLength,
                                                        uint8_t*& pCodeSlots256Data,
                                                        uint32_t& uCodeSlots256DataLength) {
    pCodeSlots1Data = NULL;
    pCodeSlots256Data = NULL;
    uCodeSlots1DataLength = 0;
    uCodeSlots256DataLength = 0;
    const uint32_t totalLength = GetCodeSignatureLength(pCSBase, signatureSize);
    if (totalLength == 0) {
        return false;
    }
    CS_SuperBlob superBlob{};
    std::memcpy(&superBlob, pCSBase, sizeof(superBlob));
    const uint32_t count = LE(superBlob.count);
    if (count > kMaximumCodeSignatureBlobCount || count > (totalLength - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex)) {
        return false;
    }
    const uint32_t indexEnd = static_cast<uint32_t>(sizeof(CS_SuperBlob) + count * sizeof(CS_BlobIndex));

    for (uint32_t i = 0; i < count; i++) {
        CS_BlobIndex blobIndex{};
        std::memcpy(&blobIndex, pCSBase + sizeof(CS_SuperBlob) + i * sizeof(CS_BlobIndex), sizeof(blobIndex));
        const uint32_t type = LE(blobIndex.type);
        if (type != CSSLOT_CODEDIRECTORY && type != CSSLOT_ALTERNATE_CODEDIRECTORIES)
            continue;
        const uint32_t slotOffset = LE(blobIndex.offset);
        if (slotOffset < indexEnd || slotOffset > totalLength ||
            totalLength - slotOffset < offsetof(CS_CodeDirectory, scatterOffset)) {
            return false;
        }
        uint8_t* pSlotBase = pCSBase + slotOffset;
        CS_CodeDirectory cdHeader{};
        std::memcpy(&cdHeader, pSlotBase, std::min<std::size_t>(totalLength - slotOffset, sizeof(cdHeader)));
        const uint32_t slotLength = LE(cdHeader.length);
        const uint32_t hashOffset = LE(cdHeader.hashOffset);
        const uint64_t hashBytes = static_cast<uint64_t>(LE(cdHeader.nCodeSlots)) * cdHeader.hashSize;
        const std::size_t requiredHeader = CodeDirectoryHeaderSize(LE(cdHeader.version));
        if (slotLength < requiredHeader || slotLength > totalLength - slotOffset || cdHeader.hashSize == 0 ||
            hashOffset < requiredHeader || hashOffset > slotLength || hashBytes > slotLength - hashOffset) {
            return false;
        }
        switch (type) {
        case CSSLOT_CODEDIRECTORY: {
            if (LE(cdHeader.length) > 8) {
                pCodeSlots1Data = pSlotBase + LE(cdHeader.hashOffset);
                uCodeSlots1DataLength = LE(cdHeader.nCodeSlots) * cdHeader.hashSize;
            }
        } break;
        case CSSLOT_ALTERNATE_CODEDIRECTORIES: {
            if (LE(cdHeader.length) > 8) {
                pCodeSlots256Data = pSlotBase + LE(cdHeader.hashOffset);
                uCodeSlots256DataLength = LE(cdHeader.nCodeSlots) * cdHeader.hashSize;
            }
        } break;
        default:
            break;
        }
    }

    return ((NULL != pCodeSlots1Data) && (NULL != pCodeSlots256Data) && uCodeSlots1DataLength > 0 &&
            uCodeSlots256DataLength > 0);
}
