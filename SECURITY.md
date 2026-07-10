# OrchardSeal security policy

## Supported versions

Security fixes target the current main branch and the latest published release unless a separate maintained release branch is announced.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the project maintainers rather than opening a public issue. Include the affected version or commit, reproduction steps, expected impact, platform, and any proposed mitigation. Avoid attaching real signing credentials or customer application content.

Particularly sensitive areas include:

- archive extraction and path handling;
- Mach-O bounds and integer calculations;
- certificate, CMS, PKCS#12, and provisioning-profile parsing;
- temporary-file creation and cleanup;
- code-signature reconstruction and replacement;
- command execution and installer integration;
- accidental disclosure of passwords, private keys, or entitlements in logs.

## Sensitive material

Never commit or publish:

- private keys, PKCS#12/PFX files, or their passwords;
- signing certificates paired with private material;
- provisioning profiles from real teams;
- customer or internal applications;
- signed IPA files or extracted proprietary bundle contents;
- audit reports that expose confidential bundle identifiers, certificate subjects, or file paths.

Use synthetic fixtures and private CI secrets. Pass passwords through protected environment variables rather than shell history when possible.

## Archive handling

OrchardSeal rejects unsafe archive paths and removes partial extraction directories after failure. Treat any archive parser or path-containment bypass as a security issue. Do not weaken fail-closed extraction to recover a malformed IPA silently.

## Responsible use

Use OrchardSeal only with applications, certificates, profiles, and devices you are authorized to inspect, modify, sign, or install.
