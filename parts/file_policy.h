#pragma once
#include <string>
#include <map>
#include <set>
#include <algorithm>
#include <cstdint>
namespace HolyFiles {
inline std::wstring Lower(std::wstring s) { for(auto& c:s) if(c>=L'A'&&c<=L'Z')c=static_cast<wchar_t>(c+L'a'-L'A');return s; }
// Incident containment, not an antivirus bypass. These exact catalog samples
// were reported as detected/deleted by the user's Kaspersky protection log.
// Matching a pinned SHA-256 proves identity, not that a payload is harmless.
inline bool ReportedUnsafePayloadSha256(const std::wstring& hash) {
    const auto value=Lower(hash);
    return value==L"407f80a9bc1dd67d01e2c2c526c08d2fd97c6828c81b74d2f9e48e7bca98d5af" ||
           value==L"318018b6203658f55a0cda96eb2788515375db8358008ddb4ff9ad3cce3e941c";
}
inline bool SafeComponent(const std::wstring& s) {
    if(s.empty()||s==L"."||s==L".."||s.back()==L'.'||s.back()==L' ')return false;
    for(auto c:s)if(c<32||c==127||std::wstring(L"<>:\"/\\|?*").find(c)!=std::wstring::npos)return false;
    auto stem=Lower(s.substr(0,s.find(L'.')));
    while(!stem.empty()&&(stem.back()==L' '||stem.back()==L'.'))stem.pop_back();
    if(stem.empty())return s.front()==L'.'; // .vscode is not dot/traversal/device syntax.
    if(stem==L"con"||stem==L"prn"||stem==L"aux"||stem==L"nul"||stem==L"conin$"||stem==L"conout$")return false;
    return !(stem.size()==4 && (stem.substr(0,3)==L"com"||stem.substr(0,3)==L"lpt") &&
        ((stem[3]>=L'0'&&stem[3]<=L'9')||stem[3]==L'\u00b9'||stem[3]==L'\u00b2'||stem[3]==L'\u00b3'));
}
inline bool LocalPath(const std::wstring& path) {
    if(path.size()<4||path[1]!=L':'||path[2]!=L'\\'||!((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z')))return false;
    for(size_t p=3;p<path.size();) {auto e=path.find(L'\\',p);if(!SafeComponent(path.substr(p,e==std::wstring::npos?e:e-p)))return false;if(e==std::wstring::npos)return true;p=e+1;}
    return false;
}
inline bool StrictChild(const std::wstring& path,const std::wstring& root) {
    return LocalPath(path)&&LocalPath(root)&&path.size()>root.size()+1&&
        Lower(path.substr(0,root.size()))==Lower(root)&&path[root.size()]==L'\\';
}
// A subtree node may be the exact root; its ancestors and prefix siblings may not.
// The caller must first bind root to the system Downloads/HolyCheck location.
inline bool FolderTarget(const std::wstring& path,const std::wstring& root) {
    return LocalPath(root)&&LocalPath(path)&&(Lower(path)==Lower(root)||StrictChild(path,root));
}
inline bool ExecutionArtifact(const std::wstring& path) {
    const auto p=Lower(path);const auto dot=p.find_last_of(L'.');if(dot==std::wstring::npos)return false;
    const auto ext=p.substr(dot);
    for(const auto* code:{L".exe",L".dll",L".com",L".scr",L".ocx",L".pyd",L".cpl",L".drv",L".sys",L".local",L".manifest",L".bat",L".cmd",L".ps1",L".psm1",L".vbs",L".vbe",L".js",L".jse",L".hta",L".wsf",L".wsh",L".msi",L".msp",L".py",L".pyc",L".pyo",L".lua",L".lnk",L".url"})if(ext==code)return true;
    return false; // DB/config/log/export files are not an unknown-code veto.
}
// One shared, bounded sleep budget for the WHOLE commit and absence check.
// The callbacks make the real production retry/cancellation policy testable
// without Windows. No retry of access-denied/invalid handles or unsafe paths.
struct DeleteRetryBudget { unsigned remainingMs=15000; };
inline bool RetryableDisposition(unsigned code) { return code==32||code==33||code==145; }
template<class Attempt,class Cancel,class Wait>
unsigned RetryDisposition(Attempt attempt,Cancel cancel,Wait wait,DeleteRetryBudget& budget) {
    unsigned delay=50;
    for(;;) {
        if(cancel())return 1223; // ERROR_CANCELLED
        const unsigned code=attempt();
        if(!code||!RetryableDisposition(code)||!budget.remainingMs)return code;
        const unsigned pause=std::min(delay,budget.remainingMs);
        budget.remainingMs-=pause;
        if(!wait(pause)||cancel())return 1223;
        delay=std::min(250u,delay*2);
    }
}
// A previous pinned payload may coexist after an upgrade, but is NEVER selected
// as the current JournalTrace launch target. No blanket exception for old EXEs.
inline bool TrustedLegacyJournalTrace(const std::wstring& leaf,const std::wstring& hash) {
    return Lower(leaf)==L"journaltracenormal.exe"&&
        hash==L"6cfd501925026f38bb97503df6211cd042e6f8b7f4e4e72457b098eb573ff775";
}
struct Planned {std::wstring path,hash;std::set<int> owners;bool conflict=false;};
class Plan {
    std::map<std::wstring,Planned> entries_;
public:
    bool Add(const std::wstring& path,const std::wstring& root,const std::wstring& hash,int owner) {
        if(!StrictChild(path,root)||hash.size()!=64||owner<0)return false;
        for(auto c:hash)if(!((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f')))return false;
        auto [it,inserted]=entries_.emplace(Lower(path),Planned{path,hash,{owner},false});
        if(!inserted){it->second.owners.insert(owner);if(it->second.hash!=hash)it->second.conflict=true;}
        return !it->second.conflict;
    }
    const std::map<std::wstring,Planned>& Entries() const{return entries_;}
    static bool Eligible(const Planned& file,const std::set<int>& held) {
        return !file.conflict && std::none_of(file.owners.begin(),file.owners.end(),[&](int i){return held.count(i)!=0;});
    }
};
}
