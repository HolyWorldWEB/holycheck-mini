#pragma once
namespace HolyUpdateConfig {
// Deployment configuration, NOT populated from the download host or manifest.
// SHA-256 of DER SubjectPublicKeyInfo of the OFFLINE CMS signing key.
// Keep empty until an independently verified key has been provisioned.
inline constexpr wchar_t kSignerSpkiSha256[] = L"";
// Empty = explicitly offline/manual manifest mode. For automatic updates set
// an operator-owned HTTPS URL on the exact host allowlist in url_policy.h.
// NEVER obtain the signing key/pin from this URL or from a downloaded manifest.
inline constexpr wchar_t kManifestUrl[] = L"";
inline constexpr unsigned long long kMinimumSequence = 1;
}
