#include "file_system.h"
#include "hash.h"
#include "json.h"
#include "utility.h"
#include "zip_archive.h"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

namespace {
    bool Check(bool condition, const char* message) {
        if (!condition) {
            std::cerr << "FAILED: " << message << '\n';
        }
        return condition;
    }
} // namespace

int main() {
    const fs::path root =
        fs::temp_directory_path() / ("orchardseal-common-" + std::to_string(Utility::GetMicroSecond()));
    const fs::path source = root / "source";
    const fs::path extracted = root / "extracted";
    const fs::path archive = root / "roundtrip.zip";
    if (!Check(FileSystem::CreateFolder(source.string().c_str()), "create source")) {
        return 1;
    }

    bool success = true;
    const fs::path executable = source / "tool";
    const fs::path unicodeFile = source / fs::u8path("\xE5\xBA\x94\xE7\x94\xA8-\xF0\x9F\x98\x80.txt");
    success &= Check(FileSystem::WriteFile(executable.string().c_str(), "payload"), "write fixture");
    success &= Check(FileSystem::WriteFile(unicodeFile.u8string().c_str(), "unicode"), "write UTF-8 path fixture");
#ifndef _WIN32
    success &= Check(chmod(executable.c_str(), 0755) == 0, "mark executable");
    success &= Check(symlink(executable.c_str(), (source / "link").c_str()) == 0, "create symlink");
    success &= Check(!ZipArchive::Archive(source.string(), archive.string(), 6), "reject source symlink");
    success &= Check(FileSystem::RemoveFile((source / "link").string().c_str()), "remove symlink");
#endif
    success &=
        Check(!ZipArchive::Archive(source.string(), (source / "self.zip").string(), 6), "reject archive inside source");
    success &= Check(ZipArchive::Archive(source.string(), archive.string(), 6), "create archive");
    success &= Check(ZipArchive::Extract(archive.string().c_str(), extracted.string().c_str()), "extract archive");
    std::string extractedContents;
    success &= Check(FileSystem::ReadFile((extracted / "tool").string().c_str(), extractedContents) &&
                         extractedContents == "payload",
                     "read extracted");
    success &= Check(FileSystem::ReadFile((extracted / unicodeFile.filename()).u8string().c_str(), extractedContents) &&
                         extractedContents == "unicode",
                     "round-trip UTF-8 archive path");
#ifndef _WIN32
    struct stat status{};
    success &= Check(stat((extracted / "tool").c_str(), &status) == 0 && (status.st_mode & 0111) != 0,
                     "preserve executable bit");
#endif

    std::string sha1;
    std::string sha256;
    success &=
        Check(!Hash::SHAFile((root / "missing").string().c_str(), sha1, sha256) && sha1.empty() && sha256.empty(),
              "missing file does not hash as empty");
    success &= Check(!Hash::SHAFile(source.string().c_str(), sha1, sha256), "directory does not hash as empty");
    const fs::path empty = root / "empty";
    success &= Check(FileSystem::WriteFile(empty.string().c_str(), ""), "write empty file");
    success &= Check(!FileSystem::CreateFolder(empty.string().c_str()), "existing file is not a directory");
    success &= Check(Hash::SHAFile(empty.string().c_str(), sha1, sha256), "hash existing empty file");
    success &= Check(FileSystem::MapFile(source.string().c_str(), 0, 0, nullptr, true) == nullptr,
                     "mapping rejects directories");

    const fs::path renameSource = root / "rename-source";
    const fs::path renameDestination = root / "rename-destination";
    success &= Check(FileSystem::WriteFile(renameSource.string().c_str(), "first") &&
                         FileSystem::Rename(renameSource.string().c_str(), renameDestination.string().c_str()),
                     "UTF-8 rename moves a file");
    success &= Check(FileSystem::WriteFile(renameSource.string().c_str(), "replacement") &&
                         !FileSystem::Rename(renameSource.string().c_str(), renameDestination.string().c_str()) &&
                         FileSystem::Rename(renameSource.string().c_str(), renameDestination.string().c_str(), true),
                     "rename replacement is explicit");

    jvalue json;
    success &= Check(json.read("{\"n\":0,\"s\":\"ok\"}"), "strict JSON accepts valid input");
    success &= Check(!json.read("01") && !json.read("1.") && !json.read("true false") && !json.read("\"x\n\""),
                     "strict JSON rejects invalid grammar and trailing content");
    std::string comments;
    for (int index = 0; index < 10000; ++index) {
        comments += "// comment\n";
    }
    comments += "true";
    success &= Check(json.read(comments), "comment skipping is iterative");

    const std::string plist =
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>text</key><string> a &amp; &lt;b&gt;\n"
        "</string><key>date</key><date>1970-01-01T00:00:00Z</date></dict></plist>";
    success &= Check(json.read_plist(plist), "parse XML plist");
    success &= Check(json["text"].as_string() == " a & <b>\n", "preserve whitespace and decode entities once");
    success &= Check(json["date"].as_date() == 0, "parse plist date as UTC");
    success &= Check(!json.read_plist("<plist><date>2023-02-29T00:00:00Z</date></plist>"), "reject invalid date");

#ifndef _WIN32
    const fs::path marker = root / "shell-marker";
    const std::string hostileArgument = "value with spaces \"quotes\" ; touch " + marker.string();
    success &=
        Check(Utility::SystemExec({"/bin/sh", "-c", "test \"$1\" = \"$2\"", "sh", hostileArgument, hostileArgument}),
              "preserve process argument boundaries");
    success &= Check(!FileSystem::IsFileExists(marker.string().c_str()), "process arguments do not invoke a shell");
#endif

    const std::string emoji = "\xF0\x9F\x98\x80";
    jvalue binarySource(jvalue::E_OBJECT);
    binarySource["emoji"] = emoji;
    std::string binaryPlist;
    success &= Check(binarySource.write_bplist(binaryPlist), "write non-BMP binary plist");
    jvalue binaryRoundTrip;
    success &= Check(binaryRoundTrip.read_plist(binaryPlist) && binaryRoundTrip["emoji"].as_string() == emoji,
                     "round-trip UTF-16 surrogate pair");

    success &= Check(json.read_plist("<plist><string>&#x1F600;</string></plist>") && json.as_string() == emoji,
                     "decode non-BMP numeric XML entity");

    const fs::path oversizedPlist = root / "oversized.plist";
    {
        std::error_code resizeError;
        fs::resize_file(oversizedPlist, static_cast<uintmax_t>(256) * 1024U * 1024U + 1U, resizeError);
        if (resizeError) {
            success &= Check(FileSystem::WriteFile(oversizedPlist.string().c_str(), "x"), "create plist size fixture");
            resizeError.clear();
            fs::resize_file(oversizedPlist, static_cast<uintmax_t>(256) * 1024U * 1024U + 1U, resizeError);
        }
        success &= Check(!resizeError, "create sparse oversized plist");
    }
    jvalue filePlist;
    success &= Check(!filePlist.read_plist_from_file("%s", oversizedPlist.string().c_str()),
                     "reject plist above bounded single-handle read cap");
#ifndef _WIN32
    const fs::path validPlist = root / "valid.plist";
    const fs::path plistLink = root / "plist-link";
    success &=
        Check(FileSystem::WriteFile(validPlist.string().c_str(), "<plist><true/></plist>"), "write plist link target");
    success &= Check(symlink(validPlist.c_str(), plistLink.c_str()) == 0, "create plist symlink");
    success &= Check(!filePlist.read_plist_from_file("%s", plistLink.string().c_str()),
                     "bounded plist read does not follow symlinks");
#endif

    FileSystem::RemoveFolder(root.string().c_str());
    return success ? 0 : 1;
}
