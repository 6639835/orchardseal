#pragma once
#include "signing_asset.h"

class CodeSignature {
  public:
    static bool SlotBuildEntitlements(const string& strEntitlements, string& strOutput);
    static bool SlotBuildDerEntitlements(const string& strEntitlements, string& strOutput);
    static bool SlotBuildRequirements(const string& strBundleID, const string& strSubjectCN, string& strOutput);
    static bool SlotBuildCodeDirectory(bool bAlternate, uint8_t* pCodeBase, uint32_t uCodeLength,
                                       uint8_t* pCodeSlotsData, uint32_t uCodeSlotsDataLength, uint64_t execSegLimit,
                                       uint64_t execSegFlags, const string& strBundleId, const string& strTeamId,
                                       const string& strInfoPlistSHA, const string& strRequirementsSlotSHA,
                                       const string& strCodeResourcesSHA, const string& strEntitlementsSlotSHA,
                                       const string& strDerEntitlementsSlotSHA, bool isExecuteArch, bool isAdhoc,
                                       string& strOutput);

    static bool SlotBuildCMSSignature(SigningAsset* pSignAsset, const string& strCodeDirectorySlot,
                                      const string& strAltnateCodeDirectorySlot, string& strOutput);

    static bool GetCodeSignatureExistsCodeSlotsData(uint8_t* pCSBase, uint32_t signatureSize, uint8_t*& pCodeSlots1Data,
                                                    uint32_t& uCodeSlots1DataLength, uint8_t*& pCodeSlots256Data,
                                                    uint32_t& uCodeSlots256DataLength);
    static uint32_t GetCodeSignatureLength(const uint8_t* pCSBase, uint32_t availableSize);

    static string _DER(const jvalue& data);
    static bool _DERChecked(const jvalue& data, string& output);
    static void _DERLength(string& strBlob, uint64_t uLength);

    static bool ParseCodeSignature(uint8_t* pCSBase, uint32_t availableSize);
    static bool SlotParseEntitlements(uint8_t* pSlotBase, CS_BlobIndex* pbi);
    static bool SlotParseDerEntitlements(uint8_t* pSlotBase, CS_BlobIndex* pbi);
    static bool SlotParseCodeDirectory(uint8_t* pSlotBase, CS_BlobIndex* pbi);
    static bool SlotParseCMSSignature(uint8_t* pSlotBase, CS_BlobIndex* pbi);
    static bool SlotParseRequirements(uint8_t* pSlotBase, CS_BlobIndex* pbi);
    static void SlotParseGeneralTailer(uint8_t* pSlotBase, uint32_t uSlotLength);
    static uint32_t SlotParseGeneralHeader(const char* szSlotName, uint8_t* pSlotBase, CS_BlobIndex* pbi);
};
