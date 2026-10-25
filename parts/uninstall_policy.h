#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace HolyUninstall {
// This is the known System Informer setup protocol ONLY, not generic flags
// for an arbitrary EXE. Keep the vendor wizard visible as requested.
inline const wchar_t* SystemInformerArguments() { return L"-uninstall"; }
// Only these already-validated vendor tokens may reach the visible wizard.
// Remove silent flags, keep only the explicit uninstall and no-restart tokens.
inline bool InteractiveVendorArguments(const std::vector<std::wstring>& tokens,std::wstring& out) {
    out.clear();
    for(auto token:tokens) {
        for(auto& c:token)if(c>=L'A'&&c<=L'Z')c=static_cast<wchar_t>(c+L'a'-L'A');
        if(token==L"/uninstall"||token==L"-uninstall"||token==L"/norestart") {
            if(!out.empty())out+=L" ";
            out+=token;
        } else if(token!=L"/s"&&token!=L"/silent"&&token!=L"/verysilent"&&
                  token!=L"/suppressmsgboxes"&&token!=L"-silent"&&token!=L"/quiet")return false;
    }
    return true;
}
// A failed product must never short-circuit attempts for the remaining products.
// Cancellation is different: do not launch any additional wizard afterwards.
template<class Cancel,class Attempt>
bool ForEachProduct(unsigned count,Cancel cancel,Attempt attempt) {
    bool complete=true;
    for(unsigned i=0;i<count;++i) {
        if(cancel())return false;
        if(!attempt(i))complete=false;
    }
    return complete&&!cancel();
}
// Win32 ERROR_SUCCESS / ERROR_MORE_DATA. Start with a real buffer, not a
// NULL-buffer probe whose success was incorrectly rejected by the old code.
template<class Query> bool ReadMsiText(Query query, std::wstring& text, unsigned& lastError) {
    text.clear(); uint32_t capacity = 256;
    for (unsigned attempt = 0; attempt != 4; ++attempt) {
        std::vector<wchar_t> data(capacity, L'\0'); uint32_t count = capacity;
        lastError = query(data.data(), count);
        if (lastError == 0) {
            if (!count || count >= capacity || data[count] != 0) return false;
            text.assign(data.data(), count);
            return text.find(L'\0') == std::wstring::npos;
        }
        if (lastError != 234 || count >= 32767 || count < capacity) return false;
        capacity = count + 1; // MSI length excludes the terminating NUL.
    }
    return false;
}
// Win32 access/sharing/lock/directory-not-empty errors may be transient while
// a vendor's final window still owns an image. No permission bypass is used.
inline bool RetryableCleanup(unsigned code) { return code == 5 || code == 32 || code == 33 || code == 145; }
enum class Removal { Complete, Cancelled, TimedOut };
struct Observation {
    bool registered = true, registryReadable = false;
    bool filePresent = true, fileReadable = false;
    bool Removed() const { return registryReadable && fileReadable && !registered && !filePresent; }
};
// Two consecutive absent/readable snapshots; no success on a registry/read
// failure, cancellation, timeout or exit code alone. Sleep is mandatory.
template<class Clock, class Probe, class Cancel, class Sleep>
Removal WaitForRemoval(uint64_t deadline, Clock clock, Probe probe, Cancel cancel, Sleep sleep) {
    unsigned absent = 0;
    for (;;) {
        if (cancel()) return Removal::Cancelled;
        if (clock() >= deadline) return Removal::TimedOut;
        absent = probe().Removed() ? absent + 1 : 0;
        if (absent >= 2) return Removal::Complete;
        sleep(500);
    }
}
}
