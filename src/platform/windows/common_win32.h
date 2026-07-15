#pragma once

#ifndef WINVER
#define WINVER 0x0602
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#ifndef _WIN32_WINDOWS
#define _WIN32_WINDOWS 0x0410
#endif

#ifndef UNICODE
#define UNICODE
#endif

#ifndef _UNICODE
#define _UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shlobj.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <direct.h>
#include "windows_text_converter.h"
#include "getopt.h"

#define PATH_MAX 4096
#define _fopen64(fp, path, mode)                                                                                       \
    {                                                                                                                  \
        fopen_s(&fp, path, mode);                                                                                      \
    }

#ifdef _M_ARM64
#pragma comment(lib, "../lib/openssl/arm64/mt/libssl.lib")
#pragma comment(lib, "../lib/openssl/arm64/mt/libcrypto.lib")
#elif defined(_M_X64)
#pragma comment(lib, "../lib/openssl/x64/mt/libssl.lib")
#pragma comment(lib, "../lib/openssl/x64/mt/libcrypto.lib")
#else
#pragma comment(lib, "../lib/openssl/x86/mt/libssl.lib")
#pragma comment(lib, "../lib/openssl/x86/mt/libcrypto.lib")
#endif

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
