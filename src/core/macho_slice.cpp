#include "common.h"
#include "json.h"
#include "macho_slice.h"
#include "code_signature.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace {

bool RangeFits(std::uint64_t offset, std::uint64_t size, std::uint64_t total)
{
    return offset <= total && size <= total - offset;
}

bool FixedNameEquals(const char* value, const char* expected)
{
    return std::strncmp(value, expected, 16) == 0;
}

bool ContainsTerminatedString(const std::uint8_t* command, std::uint32_t commandSize, std::uint32_t offset)
{
    return offset < commandSize &&
           std::memchr(command + offset, '\0', commandSize - offset) != nullptr;
}

} // namespace

bool MachOSlice::Init(std::uint8_t* base, std::uint32_t length)
{
    base_ = nullptr;
    length_ = 0;
    codeLength_ = 0;
    signatureBase_ = nullptr;
    signatureLength_ = 0;
    infoPlist_.clear();
    encrypted_ = false;
    is64Bit_ = false;
    bigEndian_ = false;
    hasEnoughSpace_ = true;
    codeSignatureSegment_ = nullptr;
    linkEditSegment_ = nullptr;
    loadCommandsFreeSpace_ = 0;
    fileType_ = 0;
    header_ = nullptr;
    headerSize_ = 0;
    execSegmentLimit_ = 0;

    if (base == nullptr || length < sizeof(std::uint32_t)) {
        return false;
    }

    std::uint32_t magic = 0;
    std::memcpy(&magic, base, sizeof(magic));
    if (magic != MH_MAGIC && magic != MH_CIGAM && magic != MH_MAGIC_64 && magic != MH_CIGAM_64) {
        return false;
    }

    is64Bit_ = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
    bigEndian_ = magic == MH_CIGAM || magic == MH_CIGAM_64;
    headerSize_ = is64Bit_ ? sizeof(mach_header_64) : sizeof(mach_header);
    if (length < headerSize_) {
        return false;
    }

    base_ = base;
    length_ = length;
    codeLength_ = length;
    header_ = reinterpret_cast<mach_header*>(base_);
    fileType_ = ByteOrder(header_->filetype);

    const std::uint32_t commandCount = ByteOrder(header_->ncmds);
    const std::uint32_t commandBytes = ByteOrder(header_->sizeofcmds);
    if (!RangeFits(headerSize_, commandBytes, length_) ||
        commandCount > commandBytes / sizeof(load_command)) {
        return false;
    }

    std::uint8_t* command = base_ + headerSize_;
    const std::uint8_t* commandEnd = command + commandBytes;
    for (std::uint32_t index = 0; index < commandCount; ++index) {
        if (static_cast<std::size_t>(commandEnd - command) < sizeof(load_command)) {
            return false;
        }

        auto* loadCommand = reinterpret_cast<load_command*>(command);
        const std::uint32_t commandType = ByteOrder(loadCommand->cmd);
        const std::uint32_t commandSize = ByteOrder(loadCommand->cmdsize);
        if (commandSize < sizeof(load_command) ||
            static_cast<std::uint64_t>(commandSize) > static_cast<std::uint64_t>(commandEnd - command)) {
            return false;
        }

        switch (commandType) {
        case LC_SEGMENT: {
            if (commandSize < sizeof(segment_command)) {
                return false;
            }
            auto* segment = reinterpret_cast<segment_command*>(command);
            const std::uint32_t sectionCount = ByteOrder(segment->nsects);
            if (sectionCount > (commandSize - sizeof(segment_command)) / sizeof(section)) {
                return false;
            }

            if (FixedNameEquals(segment->segname, "__TEXT")) {
                execSegmentLimit_ = ByteOrder(segment->vmsize);
                for (std::uint32_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
                    auto* current = reinterpret_cast<section*>(command + sizeof(segment_command) +
                                                               sizeof(section) * sectionIndex);
                    const std::uint32_t offset = ByteOrder(current->offset);
                    const std::uint32_t size = ByteOrder(current->size);
                    if (FixedNameEquals(current->sectname, "__text")) {
                        if (!RangeFits(offset, size, length_)) {
                            return false;
                        }
                        const std::uint32_t commandsEndOffset = headerSize_ + commandBytes;
                        if (offset > commandsEndOffset) {
                            const std::uint32_t available = offset - commandsEndOffset;
                            loadCommandsFreeSpace_ = loadCommandsFreeSpace_ == 0
                                ? available
                                : std::min(loadCommandsFreeSpace_, available);
                        }
                    } else if (FixedNameEquals(current->sectname, "__info_plist")) {
                        if (!RangeFits(offset, size, length_)) {
                            return false;
                        }
                        infoPlist_.append(reinterpret_cast<const char*>(base_ + offset), size);
                    }
                }
            } else if (FixedNameEquals(segment->segname, "__LINKEDIT")) {
                linkEditSegment_ = command;
            }
            break;
        }
        case LC_SEGMENT_64: {
            if (commandSize < sizeof(segment_command_64)) {
                return false;
            }
            auto* segment = reinterpret_cast<segment_command_64*>(command);
            const std::uint32_t sectionCount = ByteOrder(segment->nsects);
            if (sectionCount > (commandSize - sizeof(segment_command_64)) / sizeof(section_64)) {
                return false;
            }

            if (FixedNameEquals(segment->segname, "__TEXT")) {
                execSegmentLimit_ = ByteOrder64(segment->vmsize);
                for (std::uint32_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
                    auto* current = reinterpret_cast<section_64*>(command + sizeof(segment_command_64) +
                                                                  sizeof(section_64) * sectionIndex);
                    const std::uint32_t offset = ByteOrder(current->offset);
                    const std::uint64_t size = ByteOrder64(current->size);
                    if (FixedNameEquals(current->sectname, "__text")) {
                        if (!RangeFits(offset, size, length_)) {
                            return false;
                        }
                        const std::uint32_t commandsEndOffset = headerSize_ + commandBytes;
                        if (offset > commandsEndOffset) {
                            const std::uint32_t available = offset - commandsEndOffset;
                            loadCommandsFreeSpace_ = loadCommandsFreeSpace_ == 0
                                ? available
                                : std::min(loadCommandsFreeSpace_, available);
                        }
                    } else if (FixedNameEquals(current->sectname, "__info_plist")) {
                        if (!RangeFits(offset, size, length_) ||
                            size > std::numeric_limits<std::size_t>::max()) {
                            return false;
                        }
                        infoPlist_.append(reinterpret_cast<const char*>(base_ + offset),
                                          static_cast<std::size_t>(size));
                    }
                }
            } else if (FixedNameEquals(segment->segname, "__LINKEDIT")) {
                linkEditSegment_ = command;
            }
            break;
        }
        case LC_ENCRYPTION_INFO:
            if (commandSize < sizeof(encryption_info_command)) {
                return false;
            }
            encrypted_ = ByteOrder(reinterpret_cast<encryption_info_command*>(command)->cryptid) != 0;
            break;
        case LC_ENCRYPTION_INFO_64:
            if (commandSize < sizeof(encryption_info_command_64)) {
                return false;
            }
            encrypted_ = ByteOrder(reinterpret_cast<encryption_info_command_64*>(command)->cryptid) != 0;
            break;
        case LC_CODE_SIGNATURE: {
            if (commandSize < sizeof(codesignature_command) || codeSignatureSegment_ != nullptr) {
                return false;
            }
            auto* signatureCommand = reinterpret_cast<codesignature_command*>(command);
            const std::uint32_t dataOffset = ByteOrder(signatureCommand->dataoff);
            const std::uint32_t dataSize = ByteOrder(signatureCommand->datasize);
            if (dataOffset == 0 || !RangeFits(dataOffset, dataSize, length_)) {
                return false;
            }

            codeSignatureSegment_ = command;
            codeLength_ = dataOffset;
            signatureBase_ = base_ + dataOffset;
            if (dataSize >= sizeof(CS_SuperBlob)) {
                CS_SuperBlob superBlob {};
                std::memcpy(&superBlob, signatureBase_, sizeof(superBlob));
                if (LE(superBlob.magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
                    const std::uint32_t embeddedLength = LE(superBlob.length);
                    if (embeddedLength < sizeof(CS_SuperBlob) || embeddedLength > dataSize) {
                        return false;
                    }
                    signatureLength_ = embeddedLength;
                }
            }
            break;
        }
        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB: {
            if (commandSize < sizeof(dylib_command)) {
                return false;
            }
            auto* dylib = reinterpret_cast<dylib_command*>(command);
            const std::uint32_t nameOffset = ByteOrder(dylib->dylib.name.offset);
            if (nameOffset < sizeof(dylib_command) ||
                !ContainsTerminatedString(command, commandSize, nameOffset)) {
                return false;
            }
            break;
        }
        case LC_RPATH: {
            constexpr std::uint32_t kPathOffsetField = sizeof(load_command);
            if (commandSize < kPathOffsetField + sizeof(std::uint32_t)) {
                return false;
            }
            std::uint32_t pathOffset = 0;
            std::memcpy(&pathOffset, command + kPathOffsetField, sizeof(pathOffset));
            pathOffset = ByteOrder(pathOffset);
            if (pathOffset < kPathOffsetField + sizeof(std::uint32_t) ||
                !ContainsTerminatedString(command, commandSize, pathOffset)) {
                return false;
            }
            break;
        }
        case LC_VERSION_MIN_IPHONEOS:
            if (commandSize < sizeof(load_command) + sizeof(std::uint32_t)) {
                return false;
            }
            break;
        default:
            break;
        }

        command += commandSize;
    }

    return command == commandEnd;
}

const char* MachOSlice::GetArchitecture(int cpuType, int cpuSubType) const
{
	switch (cpuType) {
	case CPU_TYPE_ARM:
	{
		switch (cpuSubType) {
		case CPU_SUBTYPE_ARM_V6:
			return "armv6";
			break;
		case CPU_SUBTYPE_ARM_V7:
			return "armv7";
			break;
		case CPU_SUBTYPE_ARM_V7S:
			return "armv7s";
			break;
		case CPU_SUBTYPE_ARM_V7K:
			return "armv7k";
			break;
		case CPU_SUBTYPE_ARM_V8:
			return "armv8";
			break;
		}
	}
	break;
	case CPU_TYPE_ARM64:
	{
		switch (cpuSubType) {
		case CPU_SUBTYPE_ARM64_ALL:
			return "arm64";
			break;
		case CPU_SUBTYPE_ARM64_V8:
			return "arm64v8";
			break;
		case 2:
			return "arm64e";
			break;
		}
	}
	break;
	case CPU_TYPE_ARM64_32:
	{
		switch (cpuSubType) {
		case CPU_SUBTYPE_ARM64_ALL:
			return "arm64_32";
			break;
		case CPU_SUBTYPE_ARM64_32_V8:
			return "arm64e_32";
			break;
		}
	}
	break;
	case CPU_TYPE_X86:
	{
		return "x86_32";
	}
	break;
	case CPU_TYPE_X86_64:
	{
		return "x86_64";
	}
	break;
	}
	return "unknown";
}

const char* MachOSlice::GetFileType(uint32_t uFileType) const
{
	switch (uFileType) {
	case MH_OBJECT:
		return "MH_OBJECT";
		break;
	case MH_EXECUTE:
		return "MH_EXECUTE";
		break;
	case MH_FVMLIB:
		return "MH_FVMLIB";
		break;
	case MH_CORE:
		return "MH_CORE";
		break;
	case MH_PRELOAD:
		return "MH_PRELOAD";
		break;
	case MH_DYLIB:
		return "MH_DYLIB";
		break;
	case MH_DYLINKER:
		return "MH_DYLINKER";
		break;
	case MH_BUNDLE:
		return "MH_BUNDLE";
		break;
	case MH_DYLIB_STUB:
		return "MH_DYLIB_STUB";
		break;
	case MH_DSYM:
		return "MH_DSYM";
		break;
	case MH_KEXT_BUNDLE:
		return "MH_KEXT_BUNDLE";
		break;
	}
	return "MH_UNKNOWN";
}

uint32_t MachOSlice::ByteOrder(uint32_t uValue) const
{
	return bigEndian_ ? LE(uValue) : uValue;
}

std::uint64_t MachOSlice::ByteOrder64(std::uint64_t value) const
{
    return bigEndian_ ? LE(value) : value;
}

bool MachOSlice::IsExecute() const
{
	if (NULL != header_) {
		return (MH_EXECUTE == ByteOrder(header_->filetype));
	}
	return false;
}

bool MachOSlice::IsSigned() const
{
    return signatureBase_ != nullptr && signatureLength_ > 0;
}

MachOSliceInfo MachOSlice::GetInfo() const
{
    MachOSliceInfo info;
    if (header_ == nullptr) {
        return info;
    }

    info.architecture = GetArchitecture(static_cast<int>(ByteOrder(header_->cputype)),
                                        static_cast<int>(ByteOrder(header_->cpusubtype)));
    info.fileType = GetFileType(ByteOrder(header_->filetype));
    info.sizeBytes = length_;
    info.is64Bit = is64Bit_;
    info.bigEndian = bigEndian_;
    info.encrypted = encrypted_;
    info.signaturePresent = IsSigned();
    info.executable = IsExecute();
    return info;
}

void MachOSlice::PrintInfo()
{
	if (NULL == header_) {
		return;
	}

	Logger::Print("------------------------------------------------------------------\n");
	Logger::Print(">>> MachO Info: \n");
	Logger::PrintV("\tFileType: \t%s\n", GetFileType(ByteOrder(header_->filetype)));
	Logger::PrintV("\tTotalSize: \t%u (%s)\n", length_, Utility::FormatSize(length_).c_str());
	Logger::PrintV("\tPlatform: \t%u\n", is64Bit_ ? 64 : 32);
	Logger::PrintV("\tCPUArch: \t%s\n", GetArchitecture(ByteOrder(header_->cputype), ByteOrder(header_->cpusubtype)));
	Logger::PrintV("\tCPUType: \t0x%x\n", ByteOrder(header_->cputype));
	Logger::PrintV("\tCPUSubType: \t0x%x\n", ByteOrder(header_->cpusubtype));
	Logger::PrintV("\tBigEndian: \t%d\n", bigEndian_);
	Logger::PrintV("\tEncrypted: \t%d\n", encrypted_);
	Logger::PrintV("\tCommandCount: \t%d\n", ByteOrder(header_->ncmds));
	Logger::PrintV("\tCodeLength: \t%d (%s)\n", codeLength_, Utility::FormatSize(codeLength_).c_str());
	Logger::PrintV("\tSignLength: \t%d (%s)\n", signatureLength_, Utility::FormatSize(signatureLength_).c_str());
	Logger::PrintV("\tSpareLength: \t%d (%s)\n", length_ - codeLength_ - signatureLength_, Utility::FormatSize(length_ - codeLength_ - signatureLength_).c_str());

	uint8_t* pLoadCommand = base_ + headerSize_;
	for (uint32_t i = 0; i < ByteOrder(header_->ncmds); i++) {
		load_command* plc = (load_command*)pLoadCommand;
		if (LC_VERSION_MIN_IPHONEOS == ByteOrder(plc->cmd)) {
			Logger::PrintV("\tMIN_IPHONEOS: \t0x%x\n", *((uint32_t*)(pLoadCommand + sizeof(load_command))));
		} else if (LC_RPATH == ByteOrder(plc->cmd)) {
			Logger::PrintV("\tLC_RPATH: \t%s\n", (char*)(pLoadCommand + sizeof(load_command) + 4));
		}
		pLoadCommand += ByteOrder(plc->cmdsize);
	}

	bool bHasWeakDylib = false;
	Logger::PrintV("\tLC_LOAD_DYLIB: \n");
	pLoadCommand = base_ + headerSize_;
	for (uint32_t i = 0; i < ByteOrder(header_->ncmds); i++) {
		load_command* plc = (load_command*)pLoadCommand;
		if (LC_LOAD_DYLIB == ByteOrder(plc->cmd)) {
			dylib_command* dlc = (dylib_command*)pLoadCommand;
			const char* szDylib = (const char*)(pLoadCommand + ByteOrder(dlc->dylib.name.offset));
			Logger::PrintV("\t\t\t%s\n", szDylib);
		} else if (LC_LOAD_WEAK_DYLIB == ByteOrder(plc->cmd)) {
			bHasWeakDylib = true;
		}
		pLoadCommand += ByteOrder(plc->cmdsize);
	}

	if (bHasWeakDylib) {
		Logger::PrintV("\tLC_LOAD_WEAK_DYLIB: \n");
		pLoadCommand = base_ + headerSize_;
		for (uint32_t i = 0; i < ByteOrder(header_->ncmds); i++) {
			load_command* plc = (load_command*)pLoadCommand;
			if (LC_LOAD_WEAK_DYLIB == ByteOrder(plc->cmd)) {
				dylib_command* dlc = (dylib_command*)pLoadCommand;
				const char* szDylib = (const char*)(pLoadCommand + ByteOrder(dlc->dylib.name.offset));
				Logger::PrintV("\t\t\t%s (weak)\n", szDylib);
			}
			pLoadCommand += ByteOrder(plc->cmdsize);
		}
	}

	if (!infoPlist_.empty()) {
		Logger::Print("\n>>> Embedded Info.plist: \n");
		Logger::PrintV("\tlength: \t%lu\n", infoPlist_.size());

		string strInfoPlist = infoPlist_;
		Utility::StringReplace(strInfoPlist, "\n", "\n\t\t\t");
		Logger::PrintV("\tcontent: \t%s\n", strInfoPlist.c_str());

		Hash::PrintData1("\tSHA-1:  \t", infoPlist_);
		Hash::PrintData256("\tSHA-256:\t", infoPlist_);
	}

	if (NULL == signatureBase_ || signatureLength_ <= 0) {
		Logger::Warn(">>> Can't find CodeSignature segment!\n");
	} else {
		CodeSignature::ParseCodeSignature(signatureBase_);
	}

	Logger::Print("------------------------------------------------------------------\n");
}

bool MachOSlice::BuildCodeSignature(SigningAsset* pSignAsset,
	bool bForce,
	const string& strBundleId,
	const string& strInfoSHA1,
	const string& strInfoSHA256,
	const string& strCodeResourcesSHA1,
	const string& strCodeResourcesSHA256,
	string& strOutput)
{
	string strRequirementsSlot;
	string strEntitlementsSlot;
	string strDerEntitlementsSlot;

	string strEmptyEntitlements = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict/>\n</plist>\n";
	CodeSignature::SlotBuildRequirements(strBundleId, pSignAsset->SubjectCommonName(), strRequirementsSlot);
	CodeSignature::SlotBuildEntitlements(IsExecute() ? pSignAsset->EntitlementsData() : strEmptyEntitlements, strEntitlementsSlot);
	CodeSignature::SlotBuildDerEntitlements(IsExecute() ? pSignAsset->EntitlementsData() : "", strDerEntitlementsSlot);

	string strRequirementsSlotSHA1;
	string strRequirementsSlotSHA256;
	if (strRequirementsSlot.empty()) { //empty
		strRequirementsSlotSHA1.append(20, 0);
		strRequirementsSlotSHA256.append(32, 0);
	} else {
		Hash::SHA(strRequirementsSlot, strRequirementsSlotSHA1, strRequirementsSlotSHA256);
	}

	string strEntitlementsSlotSHA1;
	string strEntitlementsSlotSHA256;
	if (strEntitlementsSlot.empty()) { //empty
		strEntitlementsSlotSHA1.append(20, 0);
		strEntitlementsSlotSHA256.append(32, 0);
	} else {
		Hash::SHA(strEntitlementsSlot, strEntitlementsSlotSHA1, strEntitlementsSlotSHA256);
	}

	string strDerEntitlementsSlotSHA1;
	string strDerEntitlementsSlotSHA256;
	if (strDerEntitlementsSlot.empty()) { //empty
		strDerEntitlementsSlotSHA1.append(20, 0);
		strDerEntitlementsSlotSHA256.append(32, 0);
	} else {
		Hash::SHA(strDerEntitlementsSlot, strDerEntitlementsSlotSHA1, strDerEntitlementsSlotSHA256);
	}

	uint8_t* pCodeSlots1Data = NULL;
	uint8_t* pCodeSlots256Data = NULL;
	uint32_t uCodeSlots1DataLength = 0;
	uint32_t uCodeSlots256DataLength = 0;
	if (!bForce) {
		CodeSignature::GetCodeSignatureExistsCodeSlotsData(signatureBase_, pCodeSlots1Data, uCodeSlots1DataLength, pCodeSlots256Data, uCodeSlots256DataLength);
	}

	uint64_t uExecSegFlags = 0;
	if (MH_EXECUTE == fileType_) {
		// MAIN_BINARY must be set on the main executable for any signature flavour
		// (ad-hoc, single-binary, or full CMS). Without it, codesign --verify on
		// macOS rejects the signature as "invalid".
		uExecSegFlags = CS_EXECSEG_MAIN_BINARY;
	}

	// ALLOW_UNSIGNED is a development-only flag. It must be set *only* when
	// get-task-allow is actually true (debug build), not merely present in
	// the entitlements plist. Distribution profiles include
	// <key>get-task-allow</key><false/> and must keep this flag cleared — Apple
	// codesign never sets ALLOW_UNSIGNED for such signatures.
	if (!strEntitlementsSlot.empty()) {
		const char* pEnt = strEntitlementsSlot.data() + 8; // skip blob header
		const char* pKey = strstr(pEnt, "<key>get-task-allow</key>");
		if (NULL != pKey) {
			const char* pTrue  = strstr(pKey, "<true/>");
			const char* pFalse = strstr(pKey, "<false/>");
			if (NULL != pTrue && (NULL == pFalse || pTrue < pFalse)) {
				uExecSegFlags |= CS_EXECSEG_ALLOW_UNSIGNED;
			}
		}
	}

	string strCodeDirectorySlot;
	string strAltnateCodeDirectorySlot;
	if (!pSignAsset->Sha256Only()) {
		if (!CodeSignature::SlotBuildCodeDirectory(false,
			base_,
			codeLength_,
			pCodeSlots1Data,
			uCodeSlots1DataLength,
			execSegmentLimit_,
			uExecSegFlags,
			strBundleId,
			pSignAsset->TeamId(),
			strInfoSHA1,
			strRequirementsSlotSHA1,
			strCodeResourcesSHA1,
			strEntitlementsSlotSHA1,
			strDerEntitlementsSlotSHA1,
			IsExecute(),
			pSignAsset->IsAdHoc(),
			strCodeDirectorySlot)) {
			Logger::Error(">>> Build SHA1 CodeDirectory failed!\n");
			return false;
		}
	}

	if (!CodeSignature::SlotBuildCodeDirectory(true,
		base_,
		codeLength_,
		pCodeSlots256Data,
		uCodeSlots256DataLength,
		execSegmentLimit_,
		uExecSegFlags,
		strBundleId,
		pSignAsset->TeamId(),
		strInfoSHA256,
		strRequirementsSlotSHA256,
		strCodeResourcesSHA256,
		strEntitlementsSlotSHA256,
		strDerEntitlementsSlotSHA256,
		IsExecute(),
		pSignAsset->IsAdHoc(),
		strAltnateCodeDirectorySlot)) {
		Logger::Error(">>> Build SHA256 CodeDirectory failed!\n");
		return false;
	}
	if (pSignAsset->Sha256Only()) {
		// SHA256-based code directory is usually the alternate; however, make it the primary (and only)
		// code directory if `m_bUseSHA256Only == true`.
		strAltnateCodeDirectorySlot.swap(strCodeDirectorySlot);
	}

	string strCMSSignatureSlot;
	if (!pSignAsset->IsAdHoc()) { //adhoc remove cms signature slot
		if (!CodeSignature::SlotBuildCMSSignature(pSignAsset, strCodeDirectorySlot, strAltnateCodeDirectorySlot, strCMSSignatureSlot)) {
			Logger::Error(">>> Build CMS signature failed!\n");
			return false;
		}
	}

	uint32_t uCodeDirectorySlotLength = (uint32_t)strCodeDirectorySlot.size();
	uint32_t uRequirementsSlotLength = (uint32_t)strRequirementsSlot.size();
	uint32_t uEntitlementsSlotLength = (uint32_t)strEntitlementsSlot.size();
	uint32_t uDerEntitlementsLength = (uint32_t)strDerEntitlementsSlot.size();
	uint32_t uAltnateCodeDirectorySlotLength = (uint32_t)strAltnateCodeDirectorySlot.size();
	uint32_t uCMSSignatureSlotLength = (uint32_t)strCMSSignatureSlot.size();

	uint32_t uCodeSignBlobCount = 0;
	uCodeSignBlobCount += (uCodeDirectorySlotLength > 0) ? 1 : 0;
	uCodeSignBlobCount += (uRequirementsSlotLength > 0) ? 1 : 0;
	uCodeSignBlobCount += (uEntitlementsSlotLength > 0) ? 1 : 0;
	uCodeSignBlobCount += (uDerEntitlementsLength > 0) ? 1 : 0;
	uCodeSignBlobCount += (uAltnateCodeDirectorySlotLength > 0) ? 1 : 0;
	uCodeSignBlobCount += (uCMSSignatureSlotLength > 0) ? 1 : 0;

	uint32_t uSuperBlobHeaderLength = sizeof(CS_SuperBlob) + uCodeSignBlobCount * sizeof(CS_BlobIndex);
	uint32_t uCodeSignLength = uSuperBlobHeaderLength +
		uCodeDirectorySlotLength +
		uRequirementsSlotLength +
		uEntitlementsSlotLength +
		uDerEntitlementsLength +
		uAltnateCodeDirectorySlotLength +
		uCMSSignatureSlotLength;

	vector<CS_BlobIndex> arrBlobIndexes;
	if (uCodeDirectorySlotLength > 0) {
		CS_BlobIndex blob;
		blob.type = BE((uint32_t)CSSLOT_CODEDIRECTORY);
		blob.offset = BE(uSuperBlobHeaderLength);
		arrBlobIndexes.push_back(blob);
	}

	if (uRequirementsSlotLength > 0) {
		CS_BlobIndex blob;
		blob.type = BE((uint32_t)CSSLOT_REQUIREMENTS);
		blob.offset = BE(uSuperBlobHeaderLength + uCodeDirectorySlotLength);
		arrBlobIndexes.push_back(blob);
	}

	if (uEntitlementsSlotLength > 0) {
		CS_BlobIndex blob;
		blob.type = BE((uint32_t)CSSLOT_ENTITLEMENTS);
		blob.offset = BE(uSuperBlobHeaderLength + uCodeDirectorySlotLength + uRequirementsSlotLength);
		arrBlobIndexes.push_back(blob);
	}

	if (uDerEntitlementsLength > 0) {
		CS_BlobIndex blob;
		blob.type = BE((uint32_t)CSSLOT_DER_ENTITLEMENTS);
		blob.offset = BE(uSuperBlobHeaderLength + uCodeDirectorySlotLength + uRequirementsSlotLength + uEntitlementsSlotLength);
		arrBlobIndexes.push_back(blob);
	}

	if (uAltnateCodeDirectorySlotLength > 0) {
		CS_BlobIndex blob;
		blob.type = BE((uint32_t)CSSLOT_ALTERNATE_CODEDIRECTORIES);
		blob.offset = BE(uSuperBlobHeaderLength + uCodeDirectorySlotLength + uRequirementsSlotLength + uEntitlementsSlotLength + uDerEntitlementsLength);
		arrBlobIndexes.push_back(blob);
	}

	if (uCMSSignatureSlotLength > 0) {
		CS_BlobIndex blob;
		blob.type = BE((uint32_t)CSSLOT_SIGNATURESLOT);
		blob.offset = BE(uSuperBlobHeaderLength + uCodeDirectorySlotLength + uRequirementsSlotLength + uEntitlementsSlotLength + uDerEntitlementsLength + uAltnateCodeDirectorySlotLength);
		arrBlobIndexes.push_back(blob);
	}

	CS_SuperBlob superblob;
	superblob.magic = BE((uint32_t)CSMAGIC_EMBEDDED_SIGNATURE);
	superblob.length = BE(uCodeSignLength);
	superblob.count = BE(uCodeSignBlobCount);

	strOutput.clear();
	strOutput.reserve(uCodeSignLength);
	strOutput.append((const char*)&superblob, sizeof(superblob));
	for (size_t i = 0; i < arrBlobIndexes.size(); i++) {
		CS_BlobIndex& blob = arrBlobIndexes[i];
		strOutput.append((const char*)&blob, sizeof(blob));
	}
	strOutput += strCodeDirectorySlot;
	strOutput += strRequirementsSlot;
	strOutput += strEntitlementsSlot;
	strOutput += strDerEntitlementsSlot;
	strOutput += strAltnateCodeDirectorySlot;
	strOutput += strCMSSignatureSlot;

	if (Logger::IsDebug()) {
		FileSystem::WriteFile("./.orchardseal_debug/Requirements.slot.new", strRequirementsSlot);
		FileSystem::WriteFile("./.orchardseal_debug/Entitlements.slot.new", strEntitlementsSlot);
		FileSystem::WriteFile("./.orchardseal_debug/Entitlements.der.slot.new", strDerEntitlementsSlot);
		FileSystem::WriteFile("./.orchardseal_debug/Entitlements.plist.new", strEntitlementsSlot.data() + 8, strEntitlementsSlot.size() - 8);
		FileSystem::WriteFile("./.orchardseal_debug/CodeDirectory_SHA1.slot.new", strCodeDirectorySlot);
		FileSystem::WriteFile("./.orchardseal_debug/CodeDirectory_SHA256.slot.new", strAltnateCodeDirectorySlot);
		FileSystem::WriteFile("./.orchardseal_debug/CMSSignature.slot.new", strCMSSignatureSlot);
		FileSystem::WriteFile("./.orchardseal_debug/CMSSignature.der.new", strCMSSignatureSlot.data() + 8, strCMSSignatureSlot.size() - 8);
		FileSystem::WriteFile("./.orchardseal_debug/CodeSignature.blob.new", strOutput);
	}

	return true;
}

bool MachOSlice::Sign(SigningAsset* pSignAsset,
					bool bForce,
					const string& strBundleId,
					const string& strInfoSHA1,
					const string& strInfoSHA256,
					const string& strCodeResourcesData)
{
	if (NULL == signatureBase_) {
		hasEnoughSpace_ = false;
		Logger::Warn(">>> Can't find CodeSignature segment!\n");
		return false;
	}

	string strCodeResourcesSHA1;
	string strCodeResourcesSHA256;
	if (strCodeResourcesData.empty()) {
		strCodeResourcesSHA1.append(20, 0);
		strCodeResourcesSHA256.append(32, 0);
	} else {
		Hash::SHA(strCodeResourcesData, strCodeResourcesSHA1, strCodeResourcesSHA256);
	}

	string strCodeSignBlob;
	if (!BuildCodeSignature(pSignAsset, bForce, strBundleId, strInfoSHA1, strInfoSHA256, strCodeResourcesSHA1, strCodeResourcesSHA256, strCodeSignBlob)) {
		Logger::Error(">>> Build CodeSignature failed!\n");
		return false;
	}

	int nSpaceLength = (int)length_ - (int)codeLength_ - (int)strCodeSignBlob.size();
	if (nSpaceLength < 0) {
		hasEnoughSpace_ = false;
		Logger::WarnV(">>> No enough CodeSignature space (now: %d, need: %d).\n", (int)length_ - (int)codeLength_, (int)strCodeSignBlob.size());
		return false;
	}

	memcpy(base_ + codeLength_, strCodeSignBlob.data(), strCodeSignBlob.size());
	//memset(base_ + codeLength_ + strCodeSignBlob.size(), 0, nSpaceLength);
	return true;
}

uint32_t MachOSlice::ReallocCodeSignSpace(const string& strNewFile)
{
	FileSystem::RemoveFile(strNewFile.c_str());

	uint32_t uNewLength = codeLength_ + Utility::ByteAlign(((codeLength_ / 4096) + 1) * (20 + 32), 4096) + 32768; //32K Should Be Enough
	if (NULL == linkEditSegment_ || uNewLength <= length_) {
		return 0;
	}

	load_command* pseglc = (load_command*)linkEditSegment_;
	switch (ByteOrder(pseglc->cmd)) {
	case LC_SEGMENT:
	{
		segment_command* seglc = (segment_command*)linkEditSegment_;
		seglc->vmsize = Utility::ByteAlign(ByteOrder(seglc->vmsize) + (uNewLength - length_), 4096);
		seglc->vmsize = ByteOrder(seglc->vmsize);
		seglc->filesize = uNewLength - ByteOrder(seglc->fileoff);
		seglc->filesize = ByteOrder(seglc->filesize);
	}
	break;
	case LC_SEGMENT_64:
	{
		segment_command_64* seglc = (segment_command_64*)linkEditSegment_;
		seglc->vmsize = Utility::ByteAlign(ByteOrder((uint32_t)seglc->vmsize) + (uNewLength - length_), 4096);
		seglc->vmsize = ByteOrder((uint32_t)seglc->vmsize);
		seglc->filesize = uNewLength - ByteOrder((uint32_t)seglc->fileoff);
		seglc->filesize = ByteOrder((uint32_t)seglc->filesize);
	}
	break;
	}

	codesignature_command* pcslc = (codesignature_command*)codeSignatureSegment_;
	if (NULL == pcslc) {
		if (loadCommandsFreeSpace_ < 4) {
			Logger::Error(">>> Can't find free space of LoadCommands for CodeSignature!\n");
			return 0;
		}

		pcslc = (codesignature_command*)(base_ + headerSize_ + ByteOrder(header_->sizeofcmds));
		pcslc->cmd = ByteOrder(LC_CODE_SIGNATURE);
		pcslc->cmdsize = ByteOrder((uint32_t)sizeof(codesignature_command));
		pcslc->dataoff = ByteOrder(codeLength_);
		header_->ncmds = ByteOrder(ByteOrder(header_->ncmds) + 1);
		header_->sizeofcmds = ByteOrder(ByteOrder(header_->sizeofcmds) + sizeof(codesignature_command));
	}
	pcslc->datasize = ByteOrder(uNewLength - codeLength_);

	if (!FileSystem::AppendFile(strNewFile.c_str(), (const char*)base_, length_)) {
		return 0;
	}

	string strPadding;
	strPadding.append(uNewLength - length_, 0);
	if (!FileSystem::AppendFile(strNewFile.c_str(), strPadding)) {
		FileSystem::RemoveFile(strNewFile.c_str());
		return 0;
	}

	return uNewLength;
}

bool MachOSlice::InjectDylib(bool bWeakInject, const char* szDylibFile)
{
	if (NULL == header_) {
		return false;
	}

	uint8_t* pLoadCommand = base_ + headerSize_;
	for (uint32_t i = 0; i < ByteOrder(header_->ncmds); i++) {
		load_command* plc = (load_command*)pLoadCommand;
		uint32_t uLoadType = ByteOrder(plc->cmd);
		if (LC_LOAD_DYLIB == uLoadType || LC_LOAD_WEAK_DYLIB == uLoadType) {
			dylib_command* dlc = (dylib_command*)pLoadCommand;
			const char* szDylib = (const char*)(pLoadCommand + ByteOrder(dlc->dylib.name.offset));
			if (0 == strcmp(szDylib, szDylibFile)) {
				if ((bWeakInject && (LC_LOAD_WEAK_DYLIB != uLoadType)) || (!bWeakInject && (LC_LOAD_DYLIB != uLoadType))) {
					dlc->cmd = ByteOrder((uint32_t)(bWeakInject ? LC_LOAD_WEAK_DYLIB : LC_LOAD_DYLIB));
					const char* oldLoadType = bWeakInject ? "LC_LOAD_DYLIB" : "LC_LOAD_WEAK_DYLIB";
					const char* newLoadType = bWeakInject ? "LC_LOAD_WEAK_DYLIB" : "LC_LOAD_DYLIB";
					Logger::WarnV(">>>\t\t %s -> %s\n", oldLoadType, newLoadType);
				}
				return true;
			}
		}
		pLoadCommand += ByteOrder(plc->cmdsize);
	}

	uint32_t uDylibFileLength = (uint32_t)strlen(szDylibFile);
	uint32_t uDylibFilePadding = (8 - uDylibFileLength % 8);
	uint32_t uDylibCommandSize = sizeof(dylib_command) + uDylibFileLength + uDylibFilePadding;
	if (loadCommandsFreeSpace_ > 0 && loadCommandsFreeSpace_ < uDylibCommandSize) { // some bin doesn't have '__text'
		Logger::Error(">>> Can't find free space of LoadCommands for LC_LOAD_DYLIB or LC_LOAD_WEAK_DYLIB!\n");
		return false;
	}

	//add
	dylib_command* dlc = (dylib_command*)(base_ + headerSize_ + ByteOrder(header_->sizeofcmds));
	dlc->cmd = ByteOrder((uint32_t)(bWeakInject ? LC_LOAD_WEAK_DYLIB : LC_LOAD_DYLIB));
	dlc->cmdsize = ByteOrder(uDylibCommandSize);
	dlc->dylib.name.offset = ByteOrder((uint32_t)sizeof(dylib_command));
	dlc->dylib.timestamp = ByteOrder((uint32_t)2);
	dlc->dylib.current_version = 0;
	dlc->dylib.compatibility_version = 0;

	string strDylibFile = szDylibFile;
	strDylibFile.append(uDylibFilePadding, 0);

	uint8_t* pDylibFile = (uint8_t*)dlc + sizeof(dylib_command);
	memcpy(pDylibFile, strDylibFile.data(), strDylibFile.size());

	header_->ncmds = ByteOrder(ByteOrder(header_->ncmds) + 1);
	header_->sizeofcmds = ByteOrder(ByteOrder(header_->sizeofcmds) + uDylibCommandSize);

	return true;
}

void MachOSlice::RemoveDylibs(const set<string>& dylibs)
{
    if (header_ == nullptr || base_ == nullptr || dylibs.empty()) {
        return;
    }

    const std::uint32_t commandCount = ByteOrder(header_->ncmds);
    const std::uint32_t commandBytes = ByteOrder(header_->sizeofcmds);
    if (!RangeFits(headerSize_, commandBytes, length_)) {
        Logger::Error(">>> Invalid Mach-O load-command range.\n");
        return;
    }

    std::vector<std::uint8_t> rebuilt(commandBytes, 0);
    std::uint8_t* command = base_ + headerSize_;
    std::uint32_t rebuiltBytes = 0;
    std::uint32_t removedCount = 0;
    std::uint32_t removedBytes = 0;

    for (std::uint32_t index = 0; index < commandCount; ++index) {
        auto* loadCommand = reinterpret_cast<load_command*>(command);
        const std::uint32_t commandType = ByteOrder(loadCommand->cmd);
        const std::uint32_t commandSize = ByteOrder(loadCommand->cmdsize);
        if (commandSize < sizeof(load_command) ||
            !RangeFits(static_cast<std::uint64_t>(command - (base_ + headerSize_)),
                       commandSize,
                       commandBytes)) {
            Logger::Error(">>> Invalid Mach-O load command while removing dylibs.\n");
            return;
        }

        bool removeCommand = false;
        if (commandType == LC_LOAD_DYLIB || commandType == LC_LOAD_WEAK_DYLIB) {
            if (commandSize < sizeof(dylib_command)) {
                Logger::Error(">>> Invalid dylib load command.\n");
                return;
            }

            auto* dylibCommand = reinterpret_cast<dylib_command*>(command);
            const std::uint32_t nameOffset = ByteOrder(dylibCommand->dylib.name.offset);
            if (!ContainsTerminatedString(command, commandSize, nameOffset)) {
                Logger::Error(">>> Invalid dylib name in load command.\n");
                return;
            }

            const char* dylibPath = reinterpret_cast<const char*>(command + nameOffset);
            removeCommand = dylibs.count(dylibPath) > 0;
            Logger::PrintV("\t\t\t%s%s\n", dylibPath, removeCommand ? "\tclear" : "");
        }

        if (removeCommand) {
            ++removedCount;
            removedBytes += commandSize;
        } else {
            std::memcpy(rebuilt.data() + rebuiltBytes, command, commandSize);
            rebuiltBytes += commandSize;
        }
        command += commandSize;
    }

    if (removedCount == 0) {
        return;
    }

    std::uint8_t* loadCommandStart = base_ + headerSize_;
    std::memset(loadCommandStart, 0, commandBytes);
    std::memcpy(loadCommandStart, rebuilt.data(), rebuiltBytes);
    header_->ncmds = ByteOrder(commandCount - removedCount);
    header_->sizeofcmds = ByteOrder(rebuiltBytes);

    if (loadCommandsFreeSpace_ > 0 &&
        removedBytes <= std::numeric_limits<std::uint32_t>::max() - loadCommandsFreeSpace_) {
        loadCommandsFreeSpace_ += removedBytes;
    }
}
