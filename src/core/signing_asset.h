#pragma once

#include <cstdint>
#include <string>

#include "json.h"

class SigningAsset final {
public:
    SigningAsset() = default;
    ~SigningAsset();

    SigningAsset(const SigningAsset&) = delete;
    SigningAsset& operator=(const SigningAsset&) = delete;
    SigningAsset(SigningAsset&& other) noexcept;
    SigningAsset& operator=(SigningAsset&& other) noexcept;

    [[nodiscard]] bool Init(const std::string& certificateFile,
                            const std::string& privateKeyFile,
                            const std::string& provisioningFile,
                            const std::string& entitlementsFile,
                            const std::string& password,
                            bool adhoc,
                            bool sha256Only,
                            bool singleBinary);

    [[nodiscard]] bool GenerateCMS(const std::string& codeDirectoryHashes,
                                   const std::string& codeDirectoryHashesPlist,
                                   const std::string& codeDirectorySha1,
                                   const std::string& alternateCodeDirectorySha256,
                                   std::string& output);

    [[nodiscard]] bool IsAdHoc() const noexcept { return adhoc_; }
    [[nodiscard]] bool Sha256Only() const noexcept { return sha256Only_; }
    [[nodiscard]] bool SingleBinary() const noexcept { return singleBinary_; }
    [[nodiscard]] const std::string& TeamId() const noexcept { return teamId_; }
    [[nodiscard]] const std::string& SubjectCommonName() const noexcept { return subjectCommonName_; }
    [[nodiscard]] const std::string& ProvisioningData() const noexcept { return provisioningData_; }
    [[nodiscard]] const std::string& EntitlementsData() const noexcept { return entitlementsData_; }
    [[nodiscard]] const std::string& ApplicationIdentifier() const noexcept { return applicationIdentifier_; }

    static bool CMSError();
    // Returns the embedded WWDR intermediate (G1-G8) whose subject-name hash
    // matches issuerHash, or nullptr. Shared by signing and certificate checks.
    static const char* WWDRIntermediatePEM(unsigned long issuerHash);
    static void* GenerateASN1Type(const std::string& value);
    static bool GetCertInfo(void* certificate, jvalue& certificateInfo);
    static bool GetCMSInfo(std::uint8_t* cmsData, std::uint32_t cmsLength, jvalue& output);
    static bool GetCMSContent(const std::string& input, std::string& output);
    static void ParseCertSubject(const std::string& subject, jvalue& output);
    static std::string ASN1_TIMEtoString(const void* time);

    static const char* s_szAppleDevCACert;
    static const char* s_szAppleRootCACert;
    static const char* s_szAppleRootCACertG3;
    static const char* s_szAppleDevCACertG3;
    static const char* s_szAppleDevCACertG2;
    static const char* s_szAppleDevCACertG4;
    static const char* s_szAppleDevCACertG5;
    static const char* s_szAppleDevCACertG6;
    static const char* s_szAppleDevCACertG7;
    static const char* s_szAppleDevCACertG8;

private:
    [[nodiscard]] bool GenerateCMS(void* certificate,
                                   void* privateKey,
                                   const std::string& codeDirectoryHashes,
                                   const std::string& codeDirectoryHashesPlist,
                                   const std::string& codeDirectorySha1,
                                   const std::string& alternateCodeDirectorySha256,
                                   std::string& output);

    bool GetCertSubjectCN(void* certificate, std::string& subjectCommonName);
    bool GetCertSubjectCN(const std::string& certificateData, std::string& subjectCommonName);
    void Reset() noexcept;
    void MoveFrom(SigningAsset&& other) noexcept;

    bool adhoc_ = false;
    bool sha256Only_ = false;
    bool singleBinary_ = false;
    std::string teamId_;
    std::string subjectCommonName_;
    std::string provisioningData_;
    std::string entitlementsData_;
    std::string applicationIdentifier_;
    void* privateKey_ = nullptr;
    void* certificate_ = nullptr;
    void* certificateChain_ = nullptr; // STACK_OF(X509)* recovered from PKCS#12 input.

    class OpenSSLInit {
    public:
        OpenSSLInit();
    };
    static OpenSSLInit s_OpenSSLInit;
};
