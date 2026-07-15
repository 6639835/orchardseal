#include "common.h"
#include "certificate_check.h"
#include "signing_asset.h"
#include "mach-o.h"
#include "code_signature.h"
#include "macho_file.h"

#if defined(ORCHARDSEAL_SYSTEM_MINIZIP_NG)
#include <zip.h>
#include <unzip.h>
#elif defined(ORCHARDSEAL_SYSTEM_MINIZIP)
#include <minizip/zip.h>
#include <minizip/unzip.h>
#else
#include "zip.h"
#include "unzip.h"
#endif

#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/cms.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>
#include <ctime>
#include <cstring>
#include <limits>
#include <chrono>
#include <cctype>
#include <new>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>
#pragma comment(lib, "ws2_32.lib")
typedef int ssize_t;
#define OCSP_CLOSE_SOCKET(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/wait.h>
#include <signal.h>
#define OCSP_CLOSE_SOCKET(s) close(s)
#endif

#ifdef _WIN32
namespace {
    struct WindowsResolverContext {
        OVERLAPPED overlapped{};
        HANDLE cancellationHandle = nullptr;
        PADDRINFOEXW result = nullptr;
    };

    bool EnsureWinsockInitialized(string& error) {
        static const int startupResult = [] {
            WSADATA data{};
            return WSAStartup(MAKEWORD(2, 2), &data);
        }();
        if (startupResult != 0) {
            error = "Could not initialize Windows networking";
            return false;
        }
        // This process-lifetime Winsock reference intentionally remains active:
        // a cancelled asynchronous resolver may complete after its caller's
        // hard deadline, and WSACleanup before that completion is unsafe.
        return true;
    }

    bool Utf8ToWideForResolver(const string& input, std::wstring& output) {
        if (input.empty() || input.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
            return false;
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                               static_cast<int>(input.size()), nullptr, 0);
        if (length <= 0)
            return false;
        output.assign(static_cast<size_t>(length), L'\0');
        return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()),
                                   output.data(), length) == length;
    }

    void DestroyWindowsResolverContext(WindowsResolverContext* context) {
        if (context == nullptr)
            return;
        if (context->result != nullptr)
            FreeAddrInfoExW(context->result);
        if (context->overlapped.hEvent != nullptr)
            CloseHandle(context->overlapped.hEvent);
        delete context;
    }

    unsigned __stdcall FinishCancelledWindowsResolver(void* parameter) {
        auto* context = static_cast<WindowsResolverContext*>(parameter);
        WaitForSingleObject(context->overlapped.hEvent, INFINITE);
        GetAddrInfoExOverlappedResult(&context->overlapped);
        DestroyWindowsResolverContext(context);
        return 0;
    }
} // namespace
#endif

static bool ConnectWithTimeout(
#ifdef _WIN32
    SOCKET socketHandle,
#else
    int socketHandle,
#endif
    const sockaddr* address, int addressLength, int timeoutMilliseconds) {
#ifdef _WIN32
    u_long nonBlocking = 1;
    if (ioctlsocket(socketHandle, FIONBIO, &nonBlocking) != 0)
        return false;
    const int result = connect(socketHandle, address, addressLength);
    if (result != 0 && WSAGetLastError() != WSAEWOULDBLOCK)
        return false;
#else
    const int oldFlags = fcntl(socketHandle, F_GETFL, 0);
    if (oldFlags < 0 || fcntl(socketHandle, F_SETFL, oldFlags | O_NONBLOCK) != 0)
        return false;
    const int result = connect(socketHandle, address, addressLength);
    if (result != 0 && errno != EINPROGRESS)
        return false;
#endif
    fd_set writable;
    FD_ZERO(&writable);
    FD_SET(socketHandle, &writable);
    timeval timeout{timeoutMilliseconds / 1000, (timeoutMilliseconds % 1000) * 1000};
    const int selected = select(static_cast<int>(socketHandle) + 1, nullptr, &writable, nullptr, &timeout);
    int socketError = 0;
#ifdef _WIN32
    int errorLength = sizeof(socketError);
#else
    socklen_t errorLength = sizeof(socketError);
#endif
    const bool connected = selected == 1 &&
                           getsockopt(socketHandle, SOL_SOCKET, SO_ERROR,
#ifdef _WIN32
                                      reinterpret_cast<char*>(&socketError),
#else
                                      &socketError,
#endif
                                      &errorLength) == 0 &&
                           socketError == 0;
#ifdef _WIN32
    nonBlocking = 0;
    ioctlsocket(socketHandle, FIONBIO, &nonBlocking);
#else
    fcntl(socketHandle, F_SETFL, oldFlags);
#endif
    return connected;
}

static bool ResolveIPv4WithDeadline(const string& host, const string& port,
                                    std::chrono::steady_clock::time_point deadline, sockaddr_in& address,
                                    string& error) {
#ifdef _WIN32
    if (!EnsureWinsockInitialized(error))
        return false;
    std::wstring wideHost;
    std::wstring widePort;
    if (!Utf8ToWideForResolver(host, wideHost) || !Utf8ToWideForResolver(port, widePort)) {
        error = "OCSP resolver host or port is not valid UTF-8";
        return false;
    }

    auto* context = new (std::nothrow) WindowsResolverContext();
    if (context == nullptr) {
        error = "Could not allocate bounded DNS resolver";
        return false;
    }
    context->overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (context->overlapped.hEvent == nullptr) {
        DestroyWindowsResolverContext(context);
        error = "Could not create bounded DNS resolver event";
        return false;
    }

    ADDRINFOEXW hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    const int startResult =
        GetAddrInfoExW(wideHost.c_str(), widePort.c_str(), NS_DNS, nullptr, &hints, &context->result, nullptr,
                       &context->overlapped, nullptr, &context->cancellationHandle);
    int resolutionResult = startResult;
    if (startResult == WSA_IO_PENDING) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        const DWORD waitMilliseconds =
            remaining.count() <= 0 ? 0
                                   : static_cast<DWORD>(std::min<std::int64_t>(remaining.count() + 1, MAXDWORD - 1));
        const DWORD waitResult = WaitForSingleObject(context->overlapped.hEvent, waitMilliseconds);
        if (waitResult != WAIT_OBJECT_0) {
            GetAddrInfoExCancel(&context->cancellationHandle);
            if (WaitForSingleObject(context->overlapped.hEvent, 0) == WAIT_OBJECT_0) {
                GetAddrInfoExOverlappedResult(&context->overlapped);
                DestroyWindowsResolverContext(context);
            } else {
                uintptr_t cleanupThread =
                    _beginthreadex(nullptr, 0, FinishCancelledWindowsResolver, context, 0, nullptr);
                if (cleanupThread != 0) {
                    CloseHandle(reinterpret_cast<HANDLE>(cleanupThread));
                }
                // If the cleanup thread could not be created, retain the heap
                // context intentionally. The pending Windows operation still
                // owns it, so freeing it here would permit a use-after-free.
            }
            error = waitResult == WAIT_TIMEOUT ? "DNS resolution exceeded OCSP request deadline"
                                               : "DNS resolver wait failed";
            return false;
        }
        resolutionResult = GetAddrInfoExOverlappedResult(&context->overlapped);
    }

    bool success = false;
    if (resolutionResult == 0) {
        for (PADDRINFOEXW candidate = context->result; candidate != nullptr; candidate = candidate->ai_next) {
            if (candidate->ai_family == AF_INET && candidate->ai_addr != nullptr &&
                candidate->ai_addrlen >= sizeof(address)) {
                std::memcpy(&address, candidate->ai_addr, sizeof(address));
                success = true;
                break;
            }
        }
    }
    DestroyWindowsResolverContext(context);
    if (!success)
        error = "DNS resolution failed";
    return success;
#else
    int descriptors[2] = {-1, -1};
    if (pipe(descriptors) != 0) {
        error = "Could not create bounded DNS resolver";
        return false;
    }
    const pid_t child = fork();
    if (child < 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        error = "Could not start bounded DNS resolver";
        return false;
    }
    if (child == 0) {
        close(descriptors[0]);
        sockaddr_in resolved{};
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* result = nullptr;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) == 0 && result != nullptr &&
            result->ai_addrlen >= sizeof(resolved)) {
            std::memcpy(&resolved, result->ai_addr, sizeof(resolved));
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&resolved);
            size_t written = 0;
            while (written < sizeof(resolved)) {
                const ssize_t count = write(descriptors[1], bytes + written, sizeof(resolved) - written);
                if (count < 0 && errno == EINTR)
                    continue;
                if (count <= 0)
                    break;
                written += static_cast<size_t>(count);
            }
        }
        if (result != nullptr)
            freeaddrinfo(result);
        close(descriptors[1]);
        _exit(0);
    }

    close(descriptors[1]);
    uint8_t* output = reinterpret_cast<uint8_t*>(&address);
    size_t received = 0;
    bool success = true;
    while (received < sizeof(address)) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::microseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) {
            success = false;
            error = "DNS resolution exceeded OCSP request deadline";
            break;
        }
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(descriptors[0], &readable);
        timeval timeout{static_cast<time_t>(remaining.count() / 1000000),
                        static_cast<suseconds_t>(remaining.count() % 1000000)};
        const int selected = select(descriptors[0] + 1, &readable, nullptr, nullptr, &timeout);
        if (selected <= 0) {
            success = false;
            error = selected == 0 ? "DNS resolution exceeded OCSP request deadline" : "DNS resolver failed";
            break;
        }
        const ssize_t count = read(descriptors[0], output + received, sizeof(address) - received);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            success = false;
            error = "DNS resolution failed";
            break;
        }
        received += static_cast<size_t>(count);
    }
    close(descriptors[0]);
    // The address has already been copied through the pipe; terminating the
    // resolver also bounds any libc cleanup after resolution.
    kill(child, SIGKILL);
    int childStatus = 0;
    while (waitpid(child, &childStatus, 0) < 0 && errno == EINTR) {
    }
    return success && received == sizeof(address);
#endif
}

// ─── helpers ───────────────────────────────────────────────────────

static string SerialToHex(X509* cert) {
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (!serial)
        return "";
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (!bn)
        return "";
    char* hex = BN_bn2hex(bn);
    BN_free(bn);
    if (!hex)
        return "";
    string raw(hex);
    OPENSSL_free(hex);
    string formatted;
    for (size_t i = 0; i < raw.size(); i++) {
        if (i > 0 && i % 2 == 0)
            formatted += ':';
        formatted += raw[i];
    }
    return formatted;
}

static string TimeToISO(const ASN1_TIME* t) {
    if (!t)
        return "N/A";
    struct tm stm;
    memset(&stm, 0, sizeof(stm));
    if (ASN1_TIME_to_tm(t, &stm) != 1)
        return "N/A";
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &stm);
    return string(buf);
}

static int DaysRemaining(const ASN1_TIME* t) {
    if (!t)
        return -1;
    int day = 0, sec = 0;
    if (ASN1_TIME_diff(&day, &sec, NULL, t) != 1)
        return -1;
    if (day == 0 && sec < 0)
        return -1;
    return day;
}

static bool IsCurrentlyValid(X509* certificate) {
    return certificate != nullptr && X509_cmp_current_time(X509_get0_notBefore(certificate)) <= 0 &&
           X509_cmp_current_time(X509_get0_notAfter(certificate)) >= 0;
}

static string GetNameField(const X509_NAME* name, int nid) {
    if (!name)
        return "";
    int idx = X509_NAME_get_index_by_NID(name, nid, -1);
    if (idx < 0)
        return "";
    const X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
    if (!entry)
        return "";
    const ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
        return "";
    unsigned char* utf8 = NULL;
    int len = ASN1_STRING_to_UTF8(&utf8, data);
    if (len < 0 || !utf8)
        return "";
    string result((const char*)utf8, len);
    OPENSSL_free(utf8);
    return result;
}

static string GetKeyAlgorithm(X509* cert) {
    EVP_PKEY* pkey = X509_get0_pubkey(cert);
    if (!pkey)
        return "Unknown";
    int type = EVP_PKEY_id(pkey);
    int bits = EVP_PKEY_bits(pkey);
    string algo;
    switch (type) {
    case EVP_PKEY_RSA:
        algo = "RSA";
        break;
    case EVP_PKEY_EC:
        algo = "EC";
        break;
    case EVP_PKEY_ED25519:
        algo = "Ed25519";
        break;
    default:
        algo = OBJ_nid2sn(type);
        break;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%s %d-bit", algo.c_str(), bits);
    return string(buf);
}

static string DetectCertType(const string& cn) {
    if (cn.find("Apple Distribution") != string::npos)
        return "Apple Distribution";
    if (cn.find("iPhone Distribution") != string::npos)
        return "iPhone Distribution";
    if (cn.find("Apple Development") != string::npos)
        return "Apple Development";
    if (cn.find("iPhone Developer") != string::npos)
        return "iPhone Developer";
    if (cn.find("Mac Developer") != string::npos)
        return "Mac Developer";
    if (cn.find("Developer ID Application") != string::npos)
        return "Developer ID Application";
    if (cn.find("Developer ID Installer") != string::npos)
        return "Developer ID Installer";
    return "Certificate";
}

// ─── issuer resolution ──────────────────────────────────────────────

static X509* LoadEmbeddedCert(const char* pem) {
    BIO* bio = BIO_new_mem_buf(pem, (int)strlen(pem));
    if (!bio)
        return NULL;
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

static X509* ResolveIssuer(X509* cert) {
    const char* pem = SigningAsset::WWDRIntermediatePEM(X509_issuer_name_hash(cert));
    if (pem)
        return LoadEmbeddedCert(pem);

    X509* issuer = LoadEmbeddedCert(SigningAsset::s_szAppleDevCACertG3);
    if (issuer && X509_check_issued(issuer, cert) == X509_V_OK)
        return issuer;
    if (issuer)
        X509_free(issuer);

    issuer = LoadEmbeddedCert(SigningAsset::s_szAppleDevCACert);
    if (issuer && X509_check_issued(issuer, cert) == X509_V_OK)
        return issuer;
    if (issuer)
        X509_free(issuer);

    return NULL;
}

// ─── file type detection ────────────────────────────────────────────

enum CertFileType {
    CERT_FILE_UNKNOWN = 0,
    CERT_FILE_PROVISION,
    CERT_FILE_P12,
    CERT_FILE_CER,
    CERT_FILE_PEM,
    CERT_FILE_IPA,
    CERT_FILE_MACHO,
};

static CertFileType DetectFileType(const string& path, const string& data) {
    string ext;
    size_t dotPos = path.rfind('.');
    if (dotPos != string::npos) {
        ext = path.substr(dotPos);
        transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    }

    if (ext == ".mobileprovision" || ext == ".provisionprofile")
        return CERT_FILE_PROVISION;
    if (ext == ".p12" || ext == ".pfx")
        return CERT_FILE_P12;
    if (ext == ".cer" || ext == ".der" || ext == ".crt")
        return CERT_FILE_CER;
    if (ext == ".pem")
        return CERT_FILE_PEM;
    if (ext == ".ipa" || ext == ".zip")
        return CERT_FILE_IPA;

    if (data.size() >= 4) {
        const uint8_t* d = (const uint8_t*)data.data();
        if (d[0] == 0x50 && d[1] == 0x4B && d[2] == 0x03 && d[3] == 0x04)
            return CERT_FILE_IPA;
        if ((d[0] == 0xFE && d[1] == 0xED && d[2] == 0xFA && d[3] == 0xCE) ||
            (d[0] == 0xCE && d[1] == 0xFA && d[2] == 0xED && d[3] == 0xFE) ||
            (d[0] == 0xFE && d[1] == 0xED && d[2] == 0xFA && d[3] == 0xCF) ||
            (d[0] == 0xCF && d[1] == 0xFA && d[2] == 0xED && d[3] == 0xFE) ||
            (d[0] == 0xCA && d[1] == 0xFE && d[2] == 0xBA && d[3] == 0xBE))
            return CERT_FILE_MACHO;
        if (data.find("<?xml") != string::npos && data.find("</plist>") != string::npos)
            return CERT_FILE_PROVISION;
        if (d[0] == 0x30 && data.size() > 500)
            return CERT_FILE_P12;
        if (d[0] == 0x30)
            return CERT_FILE_CER;
        if (data.find("-----BEGIN") != string::npos)
            return CERT_FILE_PEM;
    }
    return CERT_FILE_UNKNOWN;
}

// ─── cert extraction ────────────────────────────────────────────────

static X509* LoadFromProvision(const string& data) {
    BIO* bio = BIO_new_mem_buf(data.data(), (int)data.size());
    if (!bio)
        return NULL;
    CMS_ContentInfo* cms = d2i_CMS_bio(bio, NULL);
    BIO_free(bio);
    if (!cms)
        return NULL;

    ASN1_OCTET_STRING** pos = CMS_get0_content(cms);
    if (!pos || !(*pos)) {
        CMS_ContentInfo_free(cms);
        return NULL;
    }
    string xmlContent((const char*)ASN1_STRING_get0_data(*pos), ASN1_STRING_length(*pos));
    CMS_ContentInfo_free(cms);

    size_t keyPos = xmlContent.find("<key>DeveloperCertificates</key>");
    if (keyPos == string::npos)
        return NULL;
    size_t arrayStart = xmlContent.find("<array>", keyPos);
    size_t dataStart = xmlContent.find("<data>", arrayStart);
    size_t dataEnd = xmlContent.find("</data>", dataStart);
    if (dataStart == string::npos || dataEnd == string::npos)
        return NULL;
    dataStart += 6;
    string cleanB64;
    for (size_t i = dataStart; i < dataEnd; i++) {
        if (!isspace(xmlContent[i]))
            cleanB64 += xmlContent[i];
    }

    BIO* b64Bio = BIO_new(BIO_f_base64());
    BIO* memBio = BIO_new_mem_buf(cleanB64.data(), (int)cleanB64.size());
    BIO_set_flags(b64Bio, BIO_FLAGS_BASE64_NO_NL);
    memBio = BIO_push(b64Bio, memBio);
    vector<uint8_t> certData(cleanB64.size());
    int decoded = BIO_read(memBio, certData.data(), (int)certData.size());
    BIO_free_all(memBio);
    if (decoded <= 0)
        return NULL;
    const uint8_t* p = certData.data();
    return d2i_X509(NULL, &p, decoded);
}

static X509* LoadFromP12(const string& data, const string& password, STACK_OF(X509) * *ca) {
    BIO* bio = BIO_new_mem_buf(data.data(), (int)data.size());
    if (!bio)
        return NULL;
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");
    ERR_clear_error();
    PKCS12* p12 = d2i_PKCS12_bio(bio, NULL);
    BIO_free(bio);
    if (!p12)
        return NULL;
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    if (PKCS12_parse(p12, password.c_str(), &pkey, &cert, ca) != 1) {
        PKCS12_free(p12);
        return NULL;
    }
    if (pkey)
        EVP_PKEY_free(pkey);
    PKCS12_free(p12);
    return cert;
}

static X509* LoadFromCER(const string& data) {
    const uint8_t* p = (const uint8_t*)data.data();
    X509* cert = d2i_X509(NULL, &p, (long)data.size());
    if (cert)
        return cert;
    BIO* bio = BIO_new_mem_buf(data.data(), (int)data.size());
    if (!bio)
        return NULL;
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

// ─── Leaf cert from CMS ─────────────────────────────────────────────

static X509* FindLeafCert(STACK_OF(X509) * certs) {
    if (!certs || sk_X509_num(certs) <= 0)
        return NULL;
    if (sk_X509_num(certs) == 1) {
        X509* c = sk_X509_value(certs, 0);
        X509_up_ref(c);
        return c;
    }
    for (int i = 0; i < sk_X509_num(certs); i++) {
        X509* c = sk_X509_value(certs, i);
        if (X509_check_ca(c) > 0)
            continue;
        X509_up_ref(c);
        return c;
    }
    X509* c = sk_X509_value(certs, sk_X509_num(certs) - 1);
    X509_up_ref(c);
    return c;
}

static X509* ExtractCertFromCMS(const std::uint8_t* cmsData, std::uint32_t cmsLength) {
    if (cmsData == nullptr || cmsLength == 0)
        return nullptr;
    BIO* bio = BIO_new_mem_buf(cmsData, static_cast<int>(cmsLength));
    if (!bio)
        return NULL;
    CMS_ContentInfo* cms = d2i_CMS_bio(bio, NULL);
    BIO_free(bio);
    if (!cms)
        return NULL;
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    CMS_ContentInfo_free(cms);
    X509* leaf = FindLeafCert(certs);
    if (certs)
        sk_X509_pop_free(certs, X509_free);
    return leaf;
}

// ─── Mach-O cert extraction ─────────────────────────────────────────

struct MachOSignInfo {
    bool isSigned;
    X509* cert;
};

static MachOSignInfo ExtractFromThinMachOData(std::uint8_t* base, std::uint32_t length) {
    MachOSignInfo info{false, nullptr};
    MachOSlice slice;
    if (!slice.Init(base, length) || slice.SignatureData() == nullptr || slice.SignatureSize() < sizeof(CS_SuperBlob)) {
        return info;
    }

    const std::uint8_t* signature = slice.SignatureData();
    const std::uint32_t signatureSize = slice.SignatureSize();
    CS_SuperBlob superBlob{};
    std::memcpy(&superBlob, signature, sizeof(superBlob));
    if (LE(superBlob.magic) != CSMAGIC_EMBEDDED_SIGNATURE || LE(superBlob.length) != signatureSize) {
        return info;
    }

    info.isSigned = true;
    const std::uint32_t slotCount = LE(superBlob.count);
    const std::uint64_t indexBytes = static_cast<std::uint64_t>(slotCount) * sizeof(CS_BlobIndex);
    if (indexBytes > signatureSize - sizeof(CS_SuperBlob)) {
        return info;
    }

    for (std::uint32_t index = 0; index < slotCount; ++index) {
        CS_BlobIndex blobIndex{};
        std::memcpy(&blobIndex, signature + sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex) * index, sizeof(blobIndex));
        if (LE(blobIndex.type) != CSSLOT_SIGNATURESLOT) {
            continue;
        }

        const std::uint32_t slotOffset = LE(blobIndex.offset);
        if (slotOffset > signatureSize || signatureSize - slotOffset < 2 * sizeof(std::uint32_t)) {
            continue;
        }

        std::uint32_t slotLength = 0;
        std::memcpy(&slotLength, signature + slotOffset + sizeof(std::uint32_t), sizeof(slotLength));
        slotLength = LE(slotLength);
        if (slotLength <= 2 * sizeof(std::uint32_t) || slotLength > signatureSize - slotOffset) {
            continue;
        }

        info.cert = ExtractCertFromCMS(signature + slotOffset + 2 * sizeof(std::uint32_t),
                                       slotLength - 2 * sizeof(std::uint32_t));
        break;
    }
    return info;
}

static MachOSignInfo ExtractFromMachOData(std::uint8_t* base, std::uint32_t length) {
    if (base == nullptr || length < sizeof(std::uint32_t))
        return {false, nullptr};
    std::uint32_t magic = 0;
    std::memcpy(&magic, base, sizeof(magic));
    if (magic != FAT_MAGIC && magic != FAT_CIGAM)
        return ExtractFromThinMachOData(base, length);
    if (length < sizeof(fat_header))
        return {false, nullptr};
    fat_header header{};
    std::memcpy(&header, base, sizeof(header));
    const std::uint32_t count = magic == FAT_MAGIC ? header.nfat_arch : LE(header.nfat_arch);
    if (count == 0 || count > (length - sizeof(fat_header)) / sizeof(fat_arch))
        return {false, nullptr};
    X509* representative = nullptr;
    for (std::uint32_t index = 0; index < count; ++index) {
        fat_arch architecture{};
        std::memcpy(&architecture, base + sizeof(fat_header) + index * sizeof(fat_arch), sizeof(architecture));
        const std::uint32_t offset = magic == FAT_MAGIC ? architecture.offset : LE(architecture.offset);
        const std::uint32_t size = magic == FAT_MAGIC ? architecture.size : LE(architecture.size);
        if (size == 0 || offset > length || size > length - offset) {
            X509_free(representative);
            return {false, nullptr};
        }
        MachOSignInfo current = ExtractFromThinMachOData(base + offset, size);
        if (!current.isSigned) {
            X509_free(current.cert);
            X509_free(representative);
            return {false, nullptr};
        }
        if (representative == nullptr)
            representative = current.cert;
        else
            X509_free(current.cert);
    }
    return {true, representative};
}

// ─── Read from zip (no extraction) ──────────────────────────────────

static bool ReadFileFromZipToMemory(unzFile uf, string& outData) {
    if (UNZ_OK != unzOpenCurrentFile(uf))
        return false;
    outData.clear();
    char buf[65536];
    int nRead;
    while ((nRead = unzReadCurrentFile(uf, buf, sizeof(buf))) > 0)
        outData.append(buf, nRead);
    unzCloseCurrentFile(uf);
    return (nRead >= 0);
}

static MachOSignInfo LoadFromIPA(const string& ipaPath) {
    MachOSignInfo info = {false, NULL};
    unzFile uf = unzOpen64(ipaPath.c_str());
    if (!uf)
        return info;

    unz_global_info64 gi;
    if (UNZ_OK != unzGetGlobalInfo64(uf, &gi)) {
        unzClose(uf);
        return info;
    }

    string strAppFolder, strInfoPlistData, strExecName;
    char szPath[PATH_MAX];

    for (uint64_t i = 0; i < gi.number_entry; i++) {
        unz_file_info64 fi;
        if (UNZ_OK != unzGetCurrentFileInfo64(uf, &fi, szPath, PATH_MAX, NULL, 0, NULL, 0))
            break;
        string path = szPath;
        if (path.find("Payload/") == 0 && path.find(".app/Info.plist") != string::npos) {
            size_t s1 = path.find('/'), s2 = path.find('/', s1 + 1), s3 = path.find('/', s2 + 1);
            if (s3 == string::npos) {
                strAppFolder = path.substr(0, s2 + 1);
                ReadFileFromZipToMemory(uf, strInfoPlistData);
                break;
            }
        }
        if (i < gi.number_entry - 1 && UNZ_OK != unzGoToNextFile(uf))
            break;
    }

    if (strInfoPlistData.empty()) {
        unzClose(uf);
        return info;
    }

    jvalue jvInfo;
    if (jvInfo.read_plist(strInfoPlistData))
        strExecName = jvInfo["CFBundleExecutable"].as_cstr();
    if (strExecName.empty()) {
        unzClose(uf);
        return info;
    }

    string strExecPath = strAppFolder + strExecName;

    string strBinaryData;
    if (UNZ_OK != unzGoToFirstFile(uf)) {
        unzClose(uf);
        return info;
    }
    for (uint64_t i = 0; i < gi.number_entry; i++) {
        unz_file_info64 fi;
        if (UNZ_OK != unzGetCurrentFileInfo64(uf, &fi, szPath, PATH_MAX, NULL, 0, NULL, 0))
            break;
        if (string(szPath) == strExecPath) {
            ReadFileFromZipToMemory(uf, strBinaryData);
            break;
        }
        if (i < gi.number_entry - 1 && UNZ_OK != unzGoToNextFile(uf))
            break;
    }
    unzClose(uf);

    if (strBinaryData.empty())
        return info;
    return ExtractFromMachOData((uint8_t*)strBinaryData.data(), (uint32_t)strBinaryData.size());
}

// ─── OCSP check ─────────────────────────────────────────────────────

struct OCSPResult {
    string status;
    string revokedTime;
    string errorDetail;
};

static bool ExtractOCSPUrl(X509* cert, string& host, string& port, string& path) {
    AUTHORITY_INFO_ACCESS* aia = (AUTHORITY_INFO_ACCESS*)X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);
    if (!aia)
        return false;
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (OBJ_obj2nid(ad->method) != NID_ad_OCSP)
            continue;
        if (ad->location->type != GEN_URI)
            continue;
        const unsigned char* uriData = ASN1_STRING_get0_data(ad->location->d.uniformResourceIdentifier);
        int uriLen = ASN1_STRING_length(ad->location->d.uniformResourceIdentifier);
        if (!uriData || uriLen <= 0)
            continue;
        string url((const char*)uriData, uriLen);
        // Only Apple's plain-HTTP responders are supported. Refusing arbitrary
        // certificate-controlled hosts prevents OCSP from becoming an SSRF primitive.
        size_t schemeEnd = url.find("://");
        if (schemeEnd == string::npos || url.substr(0, schemeEnd) != "http")
            continue;
        size_t hostStart = schemeEnd + 3;
        size_t pathStart = url.find('/', hostStart);
        string hostPort =
            (pathStart != string::npos) ? url.substr(hostStart, pathStart - hostStart) : url.substr(hostStart);
        path = (pathStart != string::npos) ? url.substr(pathStart) : "/";
        size_t colonPos = hostPort.find(':');
        if (colonPos != string::npos) {
            host = hostPort.substr(0, colonPos);
            port = hostPort.substr(colonPos + 1);
        } else {
            host = hostPort;
            port = "80";
        }
        const bool appleHost =
            host == "apple.com" || (host.size() > 10 && host.compare(host.size() - 10, 10, ".apple.com") == 0);
        if (!appleHost || port != "80" || path.empty() || path.front() != '/' || path.size() > 2048 ||
            path.find_first_of("\r\n") != string::npos) {
            host.clear();
            continue;
        }
        AUTHORITY_INFO_ACCESS_free(aia);
        return true;
    }
    AUTHORITY_INFO_ACCESS_free(aia);
    return false;
}

static OCSPResult PerformOCSP(X509* cert, X509* issuer) {
    OCSPResult result;
    result.status = "Error";
    if (!cert || !issuer) {
        result.errorDetail = "Missing certificate or issuer";
        return result;
    }
    if (X509_check_issued(issuer, cert) != X509_V_OK) {
        result.errorDetail = "Issuer does not sign certificate";
        return result;
    }

    string ocspHost, ocspPort, ocspPath;
    if (!ExtractOCSPUrl(cert, ocspHost, ocspPort, ocspPath)) {
        ocspHost = "ocsp.apple.com";
        ocspPort = "80";
        ocspPath = "/ocsp03-wwdr01";
        string issuerCN = GetNameField(X509_get_subject_name(issuer), NID_commonName);
        if (issuerCN.find("G6") != string::npos)
            ocspPath = "/ocsp03-wwdrg6";
        else if (issuerCN.find("G3") != string::npos)
            ocspPath = "/ocsp03-wwdrg3";
        else if (issuerCN.find("G2") != string::npos)
            ocspPath = "/ocsp03-wwdrg2";
    }

    const auto requestDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    const auto deadlineExceeded = [&] { return std::chrono::steady_clock::now() >= requestDeadline; };

    OCSP_CERTID* certId = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if (!certId) {
        result.errorDetail = "Failed to create cert ID";
        return result;
    }
    OCSP_REQUEST* req = OCSP_REQUEST_new();
    if (!req) {
        OCSP_CERTID_free(certId);
        result.errorDetail = "Request failed";
        return result;
    }
    if (!OCSP_request_add0_id(req, certId)) {
        OCSP_REQUEST_free(req);
        result.errorDetail = "Add ID failed";
        return result;
    }

    unsigned char* derReq = NULL;
    int derReqLen = i2d_OCSP_REQUEST(req, &derReq);
    if (derReqLen <= 0 || !derReq) {
        OCSP_REQUEST_free(req);
        result.errorDetail = "Serialize failed";
        return result;
    }

    sockaddr_in resolvedAddress{};
    string resolverError;
    if (!ResolveIPv4WithDeadline(ocspHost, ocspPort, requestDeadline, resolvedAddress, resolverError)) {
        OPENSSL_free(derReq);
        OCSP_REQUEST_free(req);
        result.errorDetail = resolverError;
        return result;
    }
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
#endif
        OPENSSL_free(derReq);
        OCSP_REQUEST_free(req);
        result.errorDetail = "Socket failed";
        return result;
    }
    auto applyRemainingSocketTimeout = [&]() {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(requestDeadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0)
            return false;
#ifdef _WIN32
        const DWORD timeoutMilliseconds = static_cast<DWORD>(std::min<std::int64_t>(remaining.count(), 5000));
        return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMilliseconds),
                          sizeof(timeoutMilliseconds)) == 0 &&
               setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeoutMilliseconds),
                          sizeof(timeoutMilliseconds)) == 0;
#else
        const auto bounded = std::min<std::int64_t>(remaining.count(), 5000);
        timeval timeout{static_cast<time_t>(bounded / 1000), static_cast<suseconds_t>((bounded % 1000) * 1000)};
        return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
               setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
#endif
    };
    if (!applyRemainingSocketTimeout()) {
        OCSP_CLOSE_SOCKET(sock);
        OPENSSL_free(derReq);
        OCSP_REQUEST_free(req);
        result.errorDetail = "Could not enforce OCSP network timeout";
        return result;
    }
    const auto connectBudget =
        std::chrono::duration_cast<std::chrono::milliseconds>(requestDeadline - std::chrono::steady_clock::now());
    const int connectTimeout = static_cast<int>(std::min<std::int64_t>(connectBudget.count(), 5000));
    if (connectTimeout <= 0 || !ConnectWithTimeout(sock, reinterpret_cast<const sockaddr*>(&resolvedAddress),
                                                   sizeof(resolvedAddress), connectTimeout)) {
        OCSP_CLOSE_SOCKET(sock);
        OPENSSL_free(derReq);
        OCSP_REQUEST_free(req);
        result.errorDetail = "Connect failed";
        return result;
    }

    char hdr[512];
    snprintf(hdr, sizeof(hdr),
             "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: orchardseal\r\nContent-Type: "
             "application/ocsp-request\r\nContent-Length: %d\r\n\r\n",
             ocspPath.c_str(), ocspHost.c_str(), derReqLen);
    string request(hdr);
    request.append((const char*)derReq, derReqLen);
    OPENSSL_free(derReq);
    OCSP_REQUEST_free(req);

    const char* sendPtr = request.data();
    size_t sendRemain = request.size();
    while (sendRemain > 0) {
        if (deadlineExceeded()) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "OCSP request deadline exceeded";
            return result;
        }
        if (!applyRemainingSocketTimeout()) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "Could not enforce OCSP network timeout";
            return result;
        }
        ssize_t sent = send(sock, sendPtr, (int)sendRemain, 0);
        if (sent <= 0) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "Send failed";
            return result;
        }
        sendPtr += sent;
        sendRemain -= sent;
    }

    // read response: first read until headers are complete
    string resp;
    char rb[4096];
    while (resp.find("\r\n\r\n") == string::npos) {
        if (deadlineExceeded()) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "OCSP request deadline exceeded";
            return result;
        }
        if (!applyRemainingSocketTimeout()) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "Could not enforce OCSP network timeout";
            return result;
        }
        ssize_t br = recv(sock, rb, sizeof(rb), 0);
        if (br <= 0)
            break;
        resp.append(rb, br);
        if (resp.size() > 64 * 1024) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "HTTP headers too large";
            return result;
        }
    }

    size_t he = resp.find("\r\n\r\n");
    if (he == string::npos) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "Invalid response";
        return result;
    }

    const size_t statusEnd = resp.find("\r\n");
    if (statusEnd == string::npos ||
        (resp.compare(0, 13, "HTTP/1.1 200 ") != 0 && resp.compare(0, 13, "HTTP/1.0 200 ") != 0)) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "OCSP responder returned non-200 status";
        return result;
    }

    // Strictly require one decimal Content-Length. Chunked/close-delimited
    // bodies are deliberately unsupported to keep the parser bounded.
    string headers = resp.substr(0, he + 2);
    string lowercaseHeaders = headers;
    transform(lowercaseHeaders.begin(), lowercaseHeaders.end(), lowercaseHeaders.begin(),
              [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    const string contentLengthHeader = "\r\ncontent-length:";
    const size_t clPos = lowercaseHeaders.find(contentLengthHeader);
    if (clPos == string::npos ||
        lowercaseHeaders.find(contentLengthHeader, clPos + contentLengthHeader.size()) != string::npos) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "Missing or duplicate Content-Length";
        return result;
    }
    const size_t valueStart = lowercaseHeaders.find_first_not_of(" \t", clPos + contentLengthHeader.size());
    const size_t valueEnd = lowercaseHeaders.find("\r\n", valueStart);
    if (valueStart == string::npos || valueEnd == string::npos) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "Invalid Content-Length";
        return result;
    }
    string lengthText = lowercaseHeaders.substr(valueStart, valueEnd - valueStart);
    const size_t lastDigit = lengthText.find_last_not_of(" \t");
    if (lastDigit == string::npos) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "Invalid Content-Length";
        return result;
    }
    lengthText.resize(lastDigit + 1);
    if (!std::all_of(lengthText.begin(), lengthText.end(),
                     [](unsigned char value) { return value >= '0' && value <= '9'; })) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "Invalid Content-Length";
        return result;
    }
    char* parsedEnd = nullptr;
    errno = 0;
    const unsigned long long parsedLength = std::strtoull(lengthText.c_str(), &parsedEnd, 10);
    if (errno != 0 || parsedEnd == lengthText.c_str() || *parsedEnd != '\0' || parsedLength == 0 ||
        parsedLength > static_cast<unsigned long long>(std::numeric_limits<long>::max())) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "Invalid Content-Length";
        return result;
    }
    const long contentLength = static_cast<long>(parsedLength);
    constexpr long kMaximumOCSPResponse = 1024 * 1024;
    if (contentLength < 0 || contentLength > kMaximumOCSPResponse) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "OCSP response too large";
        return result;
    }
    size_t bodyHave = resp.size() - he - 4;
    if (bodyHave > static_cast<size_t>(contentLength)) {
        OCSP_CLOSE_SOCKET(sock);
        result.errorDetail = "Trailing OCSP response data";
        return result;
    }
    while (contentLength > 0 && bodyHave < (size_t)contentLength) {
        if (deadlineExceeded()) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "OCSP request deadline exceeded";
            return result;
        }
        if (!applyRemainingSocketTimeout()) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "Could not enforce OCSP network timeout";
            return result;
        }
        ssize_t br = recv(sock, rb, sizeof(rb), 0);
        if (br <= 0) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "Truncated OCSP response";
            return result;
        }
        if (static_cast<size_t>(br) > static_cast<size_t>(contentLength) - bodyHave) {
            OCSP_CLOSE_SOCKET(sock);
            result.errorDetail = "Trailing OCSP response data";
            return result;
        }
        resp.append(rb, br);
        bodyHave += br;
    }
    OCSP_CLOSE_SOCKET(sock);

    const unsigned char* bodyPtr = (const unsigned char*)resp.data() + he + 4;
    long bodyLen = static_cast<long>(resp.size() - he - 4);
    if (bodyLen != contentLength) {
        result.errorDetail = "Empty body";
        return result;
    }

    OCSP_RESPONSE* oresp = d2i_OCSP_RESPONSE(NULL, &bodyPtr, bodyLen);
    if (!oresp || bodyPtr != reinterpret_cast<const unsigned char*>(resp.data() + resp.size())) {
        OCSP_RESPONSE_free(oresp);
        result.errorDetail = "Parse failed";
        return result;
    }
    if (OCSP_response_status(oresp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        OCSP_RESPONSE_free(oresp);
        result.errorDetail = "OCSP error";
        return result;
    }

    OCSP_BASICRESP* basic = OCSP_response_get1_basic(oresp);
    if (!basic) {
        OCSP_RESPONSE_free(oresp);
        result.errorDetail = "Parse error";
        return result;
    }

    X509_STORE* trustStore = X509_STORE_new();
    if (trustStore == nullptr) {
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(oresp);
        result.errorDetail = "Trust store allocation failed";
        return result;
    }
    auto addRoot = [&](const char* pem) {
        BIO* rootBio = BIO_new_mem_buf(pem, static_cast<int>(std::strlen(pem)));
        X509* root = rootBio == nullptr ? nullptr : PEM_read_bio_X509(rootBio, nullptr, nullptr, nullptr);
        BIO_free(rootBio);
        const bool added = root != nullptr && X509_STORE_add_cert(trustStore, root) == 1;
        X509_free(root);
        return added;
    };
    STACK_OF(X509)* verificationCerts = sk_X509_new_null();
    bool issuerAdded = verificationCerts != nullptr && X509_up_ref(issuer) == 1;
    if (issuerAdded && sk_X509_push(verificationCerts, issuer) == 0) {
        X509_free(issuer);
        issuerAdded = false;
    }
    const bool responseTrusted = issuerAdded && addRoot(SigningAsset::s_szAppleRootCACert) &&
                                 addRoot(SigningAsset::s_szAppleRootCACertG3) &&
                                 OCSP_basic_verify(basic, verificationCerts, trustStore, 0) == 1;
    if (verificationCerts != nullptr)
        sk_X509_pop_free(verificationCerts, X509_free);
    X509_STORE_free(trustStore);
    if (!responseTrusted) {
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(oresp);
        result.errorDetail = "Untrusted OCSP response signature";
        return result;
    }

    int cs = -1, reason = 0;
    ASN1_GENERALIZEDTIME *rt = NULL, *tu = NULL, *nu = NULL;
    OCSP_CERTID* lid = OCSP_cert_to_id(EVP_sha1(), cert, issuer);
    if (!lid) {
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(oresp);
        result.errorDetail = "Lookup failed";
        return result;
    }

    if (OCSP_resp_find_status(basic, lid, &cs, &reason, &rt, &tu, &nu) != 1) {
        OCSP_CERTID_free(lid);
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(oresp);
        result.status = "Unknown";
        result.errorDetail = "Not in response";
        return result;
    }
    OCSP_CERTID_free(lid);
    if (OCSP_check_validity(tu, nu, 300, 86400) != 1) {
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(oresp);
        result.errorDetail = "Stale or not-yet-valid OCSP response";
        return result;
    }

    switch (cs) {
    case V_OCSP_CERTSTATUS_GOOD:
        result.status = "Valid";
        result.errorDetail = "";
        break;
    case V_OCSP_CERTSTATUS_REVOKED:
        result.status = "Revoked";
        if (rt) {
            BIO* tb = BIO_new(BIO_s_mem());
            if (tb) {
                ASN1_GENERALIZEDTIME_print(tb, rt);
                BUF_MEM* bp = NULL;
                BIO_get_mem_ptr(tb, &bp);
                if (bp)
                    result.revokedTime.assign(bp->data, bp->length);
                BIO_free(tb);
            }
        }
        break;
    default:
        result.status = "Unknown";
        break;
    }

    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(oresp);
    return result;
}

// ─── display (simple text, matches orchardseal style) ──────────────────────

static void PrintCertInfo(X509* cert, bool showSigned, bool isSigned) {
    string cn = GetNameField(X509_get_subject_name(cert), NID_commonName);
    string org = GetNameField(X509_get_subject_name(cert), NID_organizationName);
    string ou = GetNameField(X509_get_subject_name(cert), NID_organizationalUnitName);
    string issuerCN = GetNameField(X509_get_issuer_name(cert), NID_commonName);
    string serial = SerialToHex(cert);
    string keyAlgo = GetKeyAlgorithm(cert);
    string certType = DetectCertType(cn);
    string issuedStr = TimeToISO(X509_get0_notBefore(cert));
    string expiresStr = TimeToISO(X509_get0_notAfter(cert));
    int daysLeft = DaysRemaining(X509_get0_notAfter(cert));

    if (showSigned) {
        Logger::PrintV(">>> Signed:\t%s\n", isSigned ? "Yes" : "No");
    }
    Logger::PrintV(">>> Name:\t%s\n", cn.c_str());
    Logger::PrintV(">>> Type:\t%s\n", certType.c_str());
    if (!org.empty())
        Logger::PrintV(">>> Org:\t%s\n", org.c_str());
    if (!ou.empty())
        Logger::PrintV(">>> Team:\t%s\n", ou.c_str());
    Logger::PrintV(">>> Serial:\t%s\n", serial.c_str());
    Logger::PrintV(">>> Issued:\t%s\n", issuedStr.c_str());

    if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0) {
        Logger::ErrorV(">>> Expires:\t%s (CERTIFICATE NOT YET VALID)\n", expiresStr.c_str());
    } else if (daysLeft < 0) {
        Logger::ErrorV(">>> Expires:\t%s (EXPIRED %d days ago)\n", expiresStr.c_str(), -daysLeft);
    } else if (daysLeft < 30) {
        Logger::WarnV(">>> Expires:\t%s (%d days remaining!)\n", expiresStr.c_str(), daysLeft);
    } else {
        Logger::SuccessV(">>> Expires:\t%s (%d days remaining)\n", expiresStr.c_str(), daysLeft);
    }

    Logger::PrintV(">>> Algorithm:\t%s\n", keyAlgo.c_str());
    Logger::PrintV(">>> Issuer:\t%s\n", issuerCN.c_str());
}

static int PrintOCSPResult(const OCSPResult& result) {
    if (result.status == "Valid") {
        Logger::Print(">>> OCSP:\tValid (ocsp.apple.com)\n");
    } else if (result.status == "Revoked") {
        Logger::Print(">>> OCSP:\tREVOKED\n");
        if (!result.revokedTime.empty())
            Logger::PrintV(">>> Revoked:\t%s\n", result.revokedTime.c_str());
    } else if (result.status == "Unknown") {
        Logger::Print(">>> OCSP:\tUnknown\n");
    } else {
        Logger::Print(">>> OCSP:\tError\n");
    }

    if (!result.errorDetail.empty())
        Logger::PrintV(">>> Detail:\t%s\n", result.errorDetail.c_str());

    if (result.status == "Valid")
        return 0;
    if (result.status == "Revoked")
        return 1;
    return -1;
}

// ─── main entry ─────────────────────────────────────────────────────

int CheckCertificate(const string& strFilePath, const string& strPassword) {
    string data;
    if (!FileSystem::ReadFile(strFilePath.c_str(), data) || data.empty()) {
        Logger::ErrorV(">>> Cannot read file: %s\n", strFilePath.c_str());
        return -1;
    }

    CertFileType fileType = DetectFileType(strFilePath, data);
    X509* cert = NULL;
    STACK_OF(X509)* ca = NULL;
    string fileTypeStr;
    bool isSigned = false, showSigned = false;

    switch (fileType) {
    case CERT_FILE_IPA: {
        fileTypeStr = "IPA";
        showSigned = true;
        MachOSignInfo si = LoadFromIPA(strFilePath);
        isSigned = si.isSigned;
        cert = si.cert;
        break;
    }
    case CERT_FILE_MACHO: {
        fileTypeStr = "Mach-O";
        showSigned = true;
        MachOSignInfo si = ExtractFromMachOData((uint8_t*)data.data(), (uint32_t)data.size());
        isSigned = si.isSigned;
        cert = si.cert;
        break;
    }
    case CERT_FILE_PROVISION:
        fileTypeStr = "Provision";
        cert = LoadFromProvision(data);
        break;
    case CERT_FILE_P12:
        fileTypeStr = "PKCS#12";
        cert = LoadFromP12(data, strPassword, &ca);
        break;
    case CERT_FILE_CER:
    case CERT_FILE_PEM:
        fileTypeStr = (fileType == CERT_FILE_PEM) ? "PEM" : "DER";
        cert = LoadFromCER(data);
        break;
    default:
        Logger::ErrorV(">>> Unknown file type: %s\n", strFilePath.c_str());
        return -1;
    }

    Logger::PrintV("\n>>> Check:\t%s (%s)\n", strFilePath.c_str(), fileTypeStr.c_str());

    if (showSigned && !isSigned) {
        Logger::Print(">>> Signed:\tNo\n\n");
        return -2;
    }

    if (!cert) {
        if (showSigned) {
            Logger::Print(">>> Signed:\tNo\n\n");
            return -2;
        }
        Logger::ErrorV(">>> Failed to load certificate from %s\n", strFilePath.c_str());
        return -1;
    }

    PrintCertInfo(cert, showSigned, isSigned);

    bool expired = !IsCurrentlyValid(cert);

    X509* issuer = NULL;
    if (ca && sk_X509_num(ca) > 0) {
        issuer = sk_X509_value(ca, 0);
        X509_up_ref(issuer);
    }
    if (!issuer)
        issuer = ResolveIssuer(cert);

    int retCode = 0;
    if (!issuer) {
        Logger::Print(">>> OCSP:\tSkipped (non-WWDR issuer)\n");
        retCode = expired ? 2 : 0;
    } else {
        OCSPResult ocspResult = PerformOCSP(cert, issuer);
        retCode = PrintOCSPResult(ocspResult);
        if (expired && retCode == 0)
            retCode = 2;
        X509_free(issuer);
    }

    Logger::Print("\n");

    X509_free(cert);
    if (ca)
        sk_X509_pop_free(ca, X509_free);
    return retCode;
}

// ─── Post-sign binary check ─────────────────────────────────────────

int CheckSignedBinary(const string& strAppFolder) {
    string strInfoPath = strAppFolder;
    if (strInfoPath.back() != '/')
        strInfoPath += '/';
    strInfoPath += "Info.plist";

    string strInfoPlist;
    if (!FileSystem::ReadFile(strInfoPath.c_str(), strInfoPlist) || strInfoPlist.empty())
        return -1;

    jvalue jvInfo;
    if (!jvInfo.read_plist(strInfoPlist))
        return -1;

    string strExecName = jvInfo["CFBundleExecutable"].as_cstr();
    if (strExecName.empty())
        return -1;

    string strBinaryPath = strAppFolder;
    if (strBinaryPath.back() != '/')
        strBinaryPath += '/';
    strBinaryPath += strExecName;

    return CheckCertificate(strBinaryPath, "");
}
