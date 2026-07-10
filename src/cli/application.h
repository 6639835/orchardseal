#pragma once

#include "options.h"

#include <string>

class SigningAsset;

namespace orchardseal::cli {

class Application {
public:
    explicit Application(Options options);

    int Run();

private:
    bool ValidateEnvironment() const;
    int RunCertificateCheckIfRequested() const;
    int RunAudit() const;
    int ProcessSingleMachO();
    int ProcessBundleOrArchive();
    bool CreateSignAsset(SigningAsset& asset, bool singleBinary, const std::string& provisionFile) const;

    Options options_;
};

} // namespace orchardseal::cli
