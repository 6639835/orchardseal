#include "hash.h"
#include "base64.h"
#include <openssl/sha.h>

bool Hash::SHA1(uint8_t* data, size_t size, string& strOutput)
{
	strOutput.clear();
	uint8_t hash[20];
	::SHA1(data, size, hash);
	strOutput.append((const char*)hash, 20);
	return true;
}

bool Hash::SHA256(uint8_t* data, size_t size, string& strOutput)
{
	strOutput.clear();
	uint8_t hash[32];
	::SHA256(data, size, hash);
	strOutput.append((const char*)hash, 32);
	return true;
}

bool Hash::SHA1(const string& strData, string& strOutput)
{
	return Hash::SHA1((uint8_t*)strData.data(), strData.size(), strOutput);
}

bool Hash::SHA256(const string& strData, string& strOutput)
{
	return Hash::SHA256((uint8_t*)strData.data(), strData.size(), strOutput);
}

bool Hash::SHA(const string& strData, string& strSHA1, string& strSHA256)
{
	Hash::SHA1(strData, strSHA1);
	Hash::SHA256(strData, strSHA256);
	return (!strSHA1.empty() && !strSHA256.empty());
}

bool Hash::SHA1Text(const string& strData, string& strOutput)
{
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

bool Hash::SHAFile(const char* szFile, string& strSHA1, string& strSHA256)
{
	strSHA1.clear();
	strSHA256.clear();
	size_t sSize = 0;
	uint8_t* pBase = (uint8_t*)FileSystem::MapFile(szFile, 0, 0, &sSize, true);
	// pBase may be NULL, but it's ok, because the file may be empty
	Hash::SHA1(pBase, sSize, strSHA1);
	Hash::SHA256(pBase, sSize, strSHA256);
	if (NULL != pBase && sSize > 0) {
		FileSystem::UnmapFile(pBase, sSize);
	}
	return (!strSHA1.empty() && !strSHA256.empty());
}

bool Hash::SHABase64(const string& strData, string& strSHA1Base64, string& strSHA256Base64)
{
	Base64Codec b64;
	string strSHA1;
	string strSHA256;
	SHA(strData, strSHA1, strSHA256);
	strSHA1Base64 = b64.Encode(strSHA1);
	strSHA256Base64 = b64.Encode(strSHA256);
	return (!strSHA1Base64.empty() && !strSHA256Base64.empty());
}

bool Hash::SHABase64File(const char* szFile, string& strSHA1Base64, string& strSHA256Base64)
{
	Base64Codec b64;
	string strSHA1;
	string strSHA256;
	SHAFile(szFile, strSHA1, strSHA256);
	strSHA1Base64 = b64.Encode(strSHA1);
	strSHA256Base64 = b64.Encode(strSHA256);
	return (!strSHA1Base64.empty() && !strSHA256Base64.empty());
}

void Hash::Print(const char* prefix, const uint8_t* hash, uint32_t size, const char* suffix)
{
	Logger::PrintV("%s", prefix);
	for (uint32_t i = 0; i < size; i++) {
		Logger::PrintV("%02x", hash[i]);
	}
	Logger::PrintV("%s", suffix);
}

void Hash::Print(const char* prefix, const string& strSHASum, const char* suffix)
{
	Print(prefix, (const uint8_t*)strSHASum.data(), (uint32_t)strSHASum.size(), suffix);
}

void Hash::PrintData1(const char* prefix, const string& strData, const char* suffix)
{
	string strSHASum;
	Hash::SHA1(strData, strSHASum);
	Print(prefix, strSHASum, suffix);
}

void Hash::PrintData1(const char* prefix, uint8_t* data, size_t size, const char* suffix)
{
	string strSHASum;
	Hash::SHA1(data, size, strSHASum);
	Print(prefix, strSHASum, suffix);
}

void Hash::PrintData256(const char* prefix, const string& strData, const char* suffix)
{
	string strSHASum;
	Hash::SHA256(strData, strSHASum);
	Print(prefix, strSHASum, suffix);
}

void Hash::PrintData256(const char* prefix, uint8_t* data, size_t size, const char* suffix)
{
	string strSHASum;
	Hash::SHA256(data, size, strSHASum);
	Print(prefix, strSHASum, suffix);
}
