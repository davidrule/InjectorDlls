// LookBlockNet DLL: "Look" phase — hook ws2_32!connect and dnsapi!DnsQueryW to log per-process network intents.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <shlwapi.h>
#include <unordered_map>
#include <vector>
#include <string>
#include "detours.h"

typedef INT (WINAPI *PFN_connect)(SOCKET, const struct sockaddr*, int);
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_W)(LPCWSTR, WORD, DWORD, PVOID, PDNS_RECORDW*, PVOID*);
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_A)(LPCSTR, WORD, DWORD, PVOID, PDNS_RECORDA*, PVOID*);
typedef DNS_STATUS (WINAPI *PFN_DnsQuery_UTF8)(LPCSTR, WORD, DWORD, PVOID, PDNS_RECORDA*, PVOID*);
typedef DNS_STATUS (WINAPI *PFN_DnsQueryEx)(PDNS_QUERY_REQUEST, PDNS_QUERY_RESULT, PVOID);
typedef INT (WSAAPI *PFN_WSAAddressToStringW)(LPSOCKADDR, DWORD, LPWSAPROTOCOL_INFOW, LPWSTR, LPDWORD);
typedef PCWSTR (WINAPI *PFN_InetNtopW)(INT, PVOID, PWSTR, size_t);
typedef INT (WINSOCK_API_LINKAGE *PFN_GetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
typedef INT (WINSOCK_API_LINKAGE *PFN_GetAddrInfoExW)(PCWSTR, PCWSTR, DWORD, ULONG, const ADDRINFOEXW*, PADDRINFOEXW*, struct timeval*, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
typedef INT (WINSOCK_API_LINKAGE *PFN_getaddrinfo)(const char*, const char*, const addrinfo*, addrinfo**);
typedef INT (WSAAPI *PFN_WSAConnect)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
// Late-load helpers
typedef HMODULE (WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);

static PFN_connect        p_connect = nullptr;       // ws2_32!connect
static PFN_DnsQuery_W     p_DnsQueryW = nullptr;     // dnsapi!DnsQuery_W
static PFN_DnsQuery_A     p_DnsQueryA = nullptr;     // dnsapi!DnsQuery_A
static PFN_DnsQuery_UTF8  p_DnsQueryUTF8 = nullptr;  // dnsapi!DnsQuery_UTF8
static PFN_DnsQueryEx     p_DnsQueryEx = nullptr;    // dnsapi!DnsQueryEx
static PFN_WSAAddressToStringW p_WSAAddressToStringW = nullptr; // ws2_32!WSAAddressToStringW
static PFN_InetNtopW      p_InetNtopW = nullptr;     // ws2_32!InetNtopW (if available)
static PFN_GetAddrInfoW   p_GetAddrInfoW = nullptr;  // ws2_32!GetAddrInfoW
static PFN_GetAddrInfoExW p_GetAddrInfoExW = nullptr;// ws2_32!GetAddrInfoExW
static PFN_getaddrinfo    p_getaddrinfo = nullptr;   // ws2_32!getaddrinfo (ANSI)
static PFN_WSAConnect     p_WSAConnect = nullptr;    // ws2_32!WSAConnect
// Kernel32 detours
static PFN_LoadLibraryW   p_LoadLibraryW = nullptr;
static PFN_LoadLibraryA   p_LoadLibraryA = nullptr;
static PFN_LoadLibraryExW p_LoadLibraryExW = nullptr;
static PFN_LoadLibraryExA p_LoadLibraryExA = nullptr;

static bool g_ws2Hooked = false;
static bool g_dnsHooked = false;

static wchar_t g_logPath[MAX_PATH] = {0};
static bool g_headerWritten = false;

// Map resolved IP -> domain (best-effort). Key is IPv4 DWORD; IPv6 stored as string key.
static CRITICAL_SECTION g_mapLock;
static std::unordered_map<unsigned long, std::wstring> g_ip4ToHost; // IPv4 in network order
static std::unordered_map<std::wstring, std::wstring> g_ip6ToHost;  // IPv6 numeric string -> host
static std::vector<std::wstring> g_buffer;

static void write_lines_and_clear()
{
    if (g_buffer.empty()) return;
    HANDLE h = CreateFileW(g_logPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER size{}; GetFileSizeEx(h, &size);
    if (size.QuadPart == 0 && !g_headerWritten) {
        const wchar_t* header = L"IP                    Destination\r\n------------------------------------\r\n";
        DWORD w=0; WriteFile(h, header, (DWORD)(wcslen(header)*sizeof(wchar_t)), &w, nullptr);
        g_headerWritten = true;
    }
    SetFilePointer(h, 0, nullptr, FILE_END);
    for (const auto& s : g_buffer) {
        DWORD w=0; WriteFile(h, s.c_str(), (DWORD)(s.size()*sizeof(wchar_t)), &w, nullptr);
        const wchar_t* crlf = L"\r\n"; WriteFile(h, crlf, (DWORD)(2*sizeof(wchar_t)), &w, nullptr);
    }
    CloseHandle(h);
    g_buffer.clear();
}

static void log_row(const std::wstring& ip, const std::wstring& host)
{
    wchar_t buf[256];
    // pad IP to 22 columns approx
    swprintf(buf, _countof(buf), L"%-22ls%ls", ip.c_str(), host.c_str());
    EnterCriticalSection(&g_mapLock);
    g_buffer.emplace_back(buf);
    // Flush opportunistically to limit loss if crashes
    if (g_buffer.size() >= 128) {
        write_lines_and_clear();
    }
    LeaveCriticalSection(&g_mapLock);
}

static unsigned short bswap16(unsigned short v) { return (unsigned short)((v<<8) | (v>>8)); }

static std::wstring numeric_addr_from_sockaddr(const struct sockaddr* sa)
{
    if (!sa) return L"(null)";
    if (sa->sa_family == AF_INET) {
        const sockaddr_in* s4 = (const sockaddr_in*)sa;
        wchar_t addr[64]{};
        // Prefer InetNtopW if available
        if (p_InetNtopW) {
            if (p_InetNtopW(AF_INET, (PVOID)&s4->sin_addr, addr, _countof(addr))) return addr;
        }
        // Fallback: WSAAddressToStringW
        if (p_WSAAddressToStringW) {
            wchar_t buf[96]; DWORD len = _countof(buf);
            sockaddr_in tmp = *s4; tmp.sin_port = 0; // strip port for mapping/display
            if (p_WSAAddressToStringW((LPSOCKADDR)&tmp, sizeof(tmp), nullptr, buf, &len) == 0) return buf;
        }
        // Last resort: dotted quad
        swprintf(addr, _countof(addr), L"%u.%u.%u.%u",
            s4->sin_addr.S_un.S_un_b.s_b1,
            s4->sin_addr.S_un.S_un_b.s_b2,
            s4->sin_addr.S_un.S_un_b.s_b3,
            s4->sin_addr.S_un.S_un_b.s_b4);
        return addr;
    }
    if (sa->sa_family == AF_INET6) {
        const sockaddr_in6* s6 = (const sockaddr_in6*)sa;
        wchar_t addr[80]{};
        if (p_InetNtopW) {
            if (p_InetNtopW(AF_INET6, (PVOID)&s6->sin6_addr, addr, _countof(addr))) return addr;
        }
        if (p_WSAAddressToStringW) {
            wchar_t buf[128]; DWORD len = _countof(buf);
            sockaddr_in6 tmp = *s6; tmp.sin6_port = 0;
            if (p_WSAAddressToStringW((LPSOCKADDR)&tmp, sizeof(tmp), nullptr, buf, &len) == 0) return buf;
        }
        return L"[ipv6]";
    }
    return L"(unknown)";
}

static INT WINAPI Hook_connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    std::wstring ipOnly = numeric_addr_from_sockaddr(name);
    std::wstring host = L"No available/local";
    if (name && name->sa_family == AF_INET) {
        const sockaddr_in* s4 = (const sockaddr_in*)name;
        unsigned long key = s4->sin_addr.S_un.S_addr; // network order
        EnterCriticalSection(&g_mapLock);
        auto it = g_ip4ToHost.find(key);
        if (it != g_ip4ToHost.end()) host = it->second;
        LeaveCriticalSection(&g_mapLock);
    } else if (name && name->sa_family == AF_INET6) {
        EnterCriticalSection(&g_mapLock);
        auto it6 = g_ip6ToHost.find(ipOnly);
        if (it6 != g_ip6ToHost.end()) host = it6->second;
        LeaveCriticalSection(&g_mapLock);
    }
    log_row(ipOnly, host);
    return p_connect ? p_connect(s, name, namelen) : WSAENOTSOCK;
}

static INT WINSOCK_API_LINKAGE Hook_GetAddrInfoW(PCWSTR node, PCWSTR service, const ADDRINFOW* hints, PADDRINFOW* result)
{
    INT st = p_GetAddrInfoW ? p_GetAddrInfoW(node, service, hints, result) : EAI_FAIL;
    if (st == 0 && result && *result && node) {
        EnterCriticalSection(&g_mapLock);
        for (const ADDRINFOW* ai = *result; ai != nullptr; ai = ai->ai_next) {
            if (ai->ai_addr) {
                std::wstring ip = numeric_addr_from_sockaddr(ai->ai_addr);
                if (ai->ai_family == AF_INET) {
                    const sockaddr_in* s4 = (const sockaddr_in*)ai->ai_addr;
                    unsigned long ip4 = s4->sin_addr.S_un.S_addr;
                    g_ip4ToHost[ip4] = node;
                } else if (ai->ai_family == AF_INET6) {
                    g_ip6ToHost[ip] = node;
                }
            }
        }
        LeaveCriticalSection(&g_mapLock);
    }
    return st;
}

static INT WINSOCK_API_LINKAGE Hook_getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** result)
{
    INT st = p_getaddrinfo ? p_getaddrinfo(node, service, hints, result) : EAI_FAIL;
    if (st == 0 && result && *result && node) {
        int wlen = MultiByteToWideChar(CP_ACP, 0, node, -1, nullptr, 0);
        std::wstring wnode; wnode.resize(wlen ? (wlen-1) : 0);
        if (wlen) MultiByteToWideChar(CP_ACP, 0, node, -1, &wnode[0], wlen);
        EnterCriticalSection(&g_mapLock);
        for (const addrinfo* ai = *result; ai != nullptr; ai = ai->ai_next) {
            if (ai->ai_addr) {
                std::wstring ip = numeric_addr_from_sockaddr(ai->ai_addr);
                if (ai->ai_family == AF_INET) {
                    const sockaddr_in* s4 = (const sockaddr_in*)ai->ai_addr;
                    unsigned long ip4 = s4->sin_addr.S_un.S_addr;
                    g_ip4ToHost[ip4] = wnode;
                } else if (ai->ai_family == AF_INET6) {
                    g_ip6ToHost[ip] = wnode;
                }
            }
        }
        LeaveCriticalSection(&g_mapLock);
    }
    return st;
}

static INT WSAAPI Hook_WSAConnect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF a, LPWSABUF b, LPQOS c, LPQOS d)
{
    // Log similarly to connect()
    std::wstring ipOnly = numeric_addr_from_sockaddr(name);
    std::wstring host = L"No available/local";
    if (name && name->sa_family == AF_INET) {
        const sockaddr_in* s4 = (const sockaddr_in*)name;
        unsigned long key = s4->sin_addr.S_un.S_addr;
        EnterCriticalSection(&g_mapLock);
        auto it = g_ip4ToHost.find(key);
        if (it != g_ip4ToHost.end()) host = it->second;
        LeaveCriticalSection(&g_mapLock);
    } else if (name && name->sa_family == AF_INET6) {
        EnterCriticalSection(&g_mapLock);
        auto it6 = g_ip6ToHost.find(ipOnly);
        if (it6 != g_ip6ToHost.end()) host = it6->second;
        LeaveCriticalSection(&g_mapLock);
    }
    log_row(ipOnly, host);
    return p_WSAConnect ? p_WSAConnect(s, name, namelen, a, b, c, d) : WSAENOTSOCK;
}

static DNS_STATUS WINAPI Hook_DnsQueryW(LPCWSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORDW* prec, PVOID* preserved)
{
    DNS_STATUS st = p_DnsQueryW ? p_DnsQueryW(name, type, options, extra, prec, preserved) : (DNS_STATUS)ERROR_INVALID_FUNCTION;
    if (st == 0 && prec && *prec && name) {
        // Walk results and map A/AAAA records
        PDNS_RECORDW rec = *prec;
        EnterCriticalSection(&g_mapLock);
        for (auto p = rec; p != nullptr; p = p->pNext) {
            if (p->wType == DNS_TYPE_A) {
                unsigned long ip = p->Data.A.IpAddress; // network order
                g_ip4ToHost[ip] = name;
            } else if (p->wType == DNS_TYPE_AAAA) {
                sockaddr_in6 s6{}; s6.sin6_family = AF_INET6; memcpy(&s6.sin6_addr, &p->Data.AAAA.Ip6Address, sizeof(IN6_ADDR));
                std::wstring v6 = numeric_addr_from_sockaddr((sockaddr*)&s6);
                if (!v6.empty()) g_ip6ToHost[v6] = name;
            }
        }
        LeaveCriticalSection(&g_mapLock);
    }
    return st;
}

static DNS_STATUS WINAPI Hook_DnsQueryA(LPCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORDA* prec, PVOID* preserved)
{
    DNS_STATUS st = p_DnsQueryA ? p_DnsQueryA(name, type, options, extra, prec, preserved) : (DNS_STATUS)ERROR_INVALID_FUNCTION;
    if (st == 0 && prec && *prec && name) {
        // convert host to wide for map value
        int wlen = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
        std::wstring wname; wname.resize(wlen ? (wlen-1) : 0);
        if (wlen) MultiByteToWideChar(CP_ACP, 0, name, -1, &wname[0], wlen);
        PDNS_RECORDA rec = *prec;
        EnterCriticalSection(&g_mapLock);
        for (auto p = rec; p != nullptr; p = p->pNext) {
            if (p->wType == DNS_TYPE_A) {
                unsigned long ip = p->Data.A.IpAddress; g_ip4ToHost[ip] = wname;
            }
        }
        LeaveCriticalSection(&g_mapLock);
    }
    return st;
}

static DNS_STATUS WINAPI Hook_DnsQueryUTF8(LPCSTR name, WORD type, DWORD options, PVOID extra, PDNS_RECORDA* prec, PVOID* preserved)
{
    DNS_STATUS st = p_DnsQueryUTF8 ? p_DnsQueryUTF8(name, type, options, extra, prec, preserved) : (DNS_STATUS)ERROR_INVALID_FUNCTION;
    if (st == 0 && prec && *prec && name) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, name, -1, nullptr, 0);
        std::wstring wname; wname.resize(wlen ? (wlen-1) : 0);
        if (wlen) MultiByteToWideChar(CP_UTF8, 0, name, -1, &wname[0], wlen);
        PDNS_RECORDA rec = *prec;
        EnterCriticalSection(&g_mapLock);
        for (auto p = rec; p != nullptr; p = p->pNext) {
            if (p->wType == DNS_TYPE_A) {
                unsigned long ip = p->Data.A.IpAddress; g_ip4ToHost[ip] = wname;
            }
        }
        LeaveCriticalSection(&g_mapLock);
    }
    return st;
}

static DNS_STATUS WINAPI Hook_DnsQueryEx(PDNS_QUERY_REQUEST req, PDNS_QUERY_RESULT res, PVOID preserved)
{
    DNS_STATUS st = p_DnsQueryEx ? p_DnsQueryEx(req, res, preserved) : (DNS_STATUS)ERROR_INVALID_FUNCTION;
    if (st == 0 && res && res->pQueryRecords && req && req->QueryName) {
        std::wstring name(req->QueryName);
        EnterCriticalSection(&g_mapLock);
        for (PDNS_RECORD p = res->pQueryRecords; p != nullptr; p = p->pNext) {
            if (p->wType == DNS_TYPE_A) {
                unsigned long ip = p->Data.A.IpAddress; g_ip4ToHost[ip] = name;
            } else if (p->wType == DNS_TYPE_AAAA) {
                sockaddr_in6 s6{}; s6.sin6_family = AF_INET6; memcpy(&s6.sin6_addr, &p->Data.AAAA.Ip6Address, sizeof(IN6_ADDR));
                std::wstring v6 = numeric_addr_from_sockaddr((sockaddr*)&s6);
                if (!v6.empty()) g_ip6ToHost[v6] = name;
            }
        }
        LeaveCriticalSection(&g_mapLock);
    }
    return st;
}

static void ensure_hooks()
{
    // ws2_32 hooks
    if (!g_ws2Hooked) {
        HMODULE hWs2 = GetModuleHandleW(L"ws2_32.dll");
        if (hWs2) {
            if (!p_connect) p_connect = (PFN_connect)GetProcAddress(hWs2, "connect");
            if (!p_WSAConnect) p_WSAConnect = (PFN_WSAConnect)GetProcAddress(hWs2, "WSAConnect");
            if (!p_GetAddrInfoW) p_GetAddrInfoW = (PFN_GetAddrInfoW)GetProcAddress(hWs2, "GetAddrInfoW");
            if (!p_GetAddrInfoExW) p_GetAddrInfoExW = (PFN_GetAddrInfoExW)GetProcAddress(hWs2, "GetAddrInfoExW");
            if (!p_getaddrinfo) p_getaddrinfo = (PFN_getaddrinfo)GetProcAddress(hWs2, "getaddrinfo");
            if (!p_WSAAddressToStringW) p_WSAAddressToStringW = (PFN_WSAAddressToStringW)GetProcAddress(hWs2, "WSAAddressToStringW");
            if (!p_InetNtopW) p_InetNtopW = (PFN_InetNtopW)GetProcAddress(hWs2, "InetNtopW");
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            if (p_connect) DetourAttach(&(PVOID&)p_connect, Hook_connect);
            if (p_WSAConnect) DetourAttach(&(PVOID&)p_WSAConnect, Hook_WSAConnect);
            if (p_GetAddrInfoW) DetourAttach(&(PVOID&)p_GetAddrInfoW, Hook_GetAddrInfoW);
            if (p_getaddrinfo) DetourAttach(&(PVOID&)p_getaddrinfo, Hook_getaddrinfo);
            DetourTransactionCommit();
            g_ws2Hooked = (p_connect != nullptr);
        }
    }
    // dnsapi hooks
    if (!g_dnsHooked) {
        HMODULE hDns = GetModuleHandleW(L"dnsapi.dll");
        if (hDns) {
            if (!p_DnsQueryW) p_DnsQueryW = (PFN_DnsQuery_W)GetProcAddress(hDns, "DnsQuery_W");
            if (!p_DnsQueryA) p_DnsQueryA = (PFN_DnsQuery_A)GetProcAddress(hDns, "DnsQuery_A");
            if (!p_DnsQueryUTF8) p_DnsQueryUTF8 = (PFN_DnsQuery_UTF8)GetProcAddress(hDns, "DnsQuery_UTF8");
            if (!p_DnsQueryEx) p_DnsQueryEx = (PFN_DnsQueryEx)GetProcAddress(hDns, "DnsQueryEx");
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            if (p_DnsQueryW) DetourAttach(&(PVOID&)p_DnsQueryW, Hook_DnsQueryW);
            if (p_DnsQueryA) DetourAttach(&(PVOID&)p_DnsQueryA, Hook_DnsQueryA);
            if (p_DnsQueryUTF8) DetourAttach(&(PVOID&)p_DnsQueryUTF8, Hook_DnsQueryUTF8);
            if (p_DnsQueryEx) DetourAttach(&(PVOID&)p_DnsQueryEx, Hook_DnsQueryEx);
            DetourTransactionCommit();
            g_dnsHooked = (p_DnsQueryW || p_DnsQueryA || p_DnsQueryUTF8 || p_DnsQueryEx);
        }
    }
}

static bool is_target_module(HMODULE h, const wchar_t* target)
{
    if (!h) return false;
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(h, path, MAX_PATH)) return false;
    const wchar_t* base = PathFindFileNameW(path);
    return (base && _wcsicmp(base, target) == 0);
}

// Kernel32 detours to catch late loads
static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR lpLibFileName)
{
    HMODULE h = p_LoadLibraryW ? p_LoadLibraryW(lpLibFileName) : NULL;
    if (h && (is_target_module(h, L"ws2_32.dll") || is_target_module(h, L"dnsapi.dll"))) {
        ensure_hooks();
    }
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryA(LPCSTR lpLibFileName)
{
    HMODULE h = p_LoadLibraryA ? p_LoadLibraryA(lpLibFileName) : NULL;
    if (h && (is_target_module(h, L"ws2_32.dll") || is_target_module(h, L"dnsapi.dll"))) {
        ensure_hooks();
    }
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE h = p_LoadLibraryExW ? p_LoadLibraryExW(lpLibFileName, hFile, dwFlags) : NULL;
    if (h && (is_target_module(h, L"ws2_32.dll") || is_target_module(h, L"dnsapi.dll"))) {
        ensure_hooks();
    }
    return h;
}
static HMODULE WINAPI Hook_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
    HMODULE h = p_LoadLibraryExA ? p_LoadLibraryExA(lpLibFileName, hFile, dwFlags) : NULL;
    if (h && (is_target_module(h, L"ws2_32.dll") || is_target_module(h, L"dnsapi.dll"))) {
        ensure_hooks();
    }
    return h;
}

static void install_hooks()
{
    // Attach kernel32 loaders to detect late ws2_32/dnsapi loads
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        p_LoadLibraryW   = (PFN_LoadLibraryW)GetProcAddress(hK32, "LoadLibraryW");
        p_LoadLibraryA   = (PFN_LoadLibraryA)GetProcAddress(hK32, "LoadLibraryA");
        p_LoadLibraryExW = (PFN_LoadLibraryExW)GetProcAddress(hK32, "LoadLibraryExW");
        p_LoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(hK32, "LoadLibraryExA");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (p_LoadLibraryW)   DetourAttach(&(PVOID&)p_LoadLibraryW, Hook_LoadLibraryW);
        if (p_LoadLibraryA)   DetourAttach(&(PVOID&)p_LoadLibraryA, Hook_LoadLibraryA);
        if (p_LoadLibraryExW) DetourAttach(&(PVOID&)p_LoadLibraryExW, Hook_LoadLibraryExW);
        if (p_LoadLibraryExA) DetourAttach(&(PVOID&)p_LoadLibraryExA, Hook_LoadLibraryExA);
        DetourTransactionCommit();
    }

    // Try to install immediate hooks if modules are already loaded
    ensure_hooks();
}

static void init_paths(HINSTANCE h)
{
    wchar_t path[MAX_PATH]; GetModuleFileNameW(h, path, MAX_PATH);
    // trim to directory
    for (int i = (int)wcslen(path) - 1; i >= 0; --i) { if (path[i] == L'\\' || path[i]==L'/') { path[i] = 0; break; } }
    wsprintfW(g_logPath, L"%s\\LBN_looker.log", path);
    
    // Create the log file immediately with a startup message
    log_row(L"LookBlockNet", L"Initialized and hooks installed");
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_mapLock);
        init_paths(h);
        install_hooks();
        
        // Show a message box confirming the DLL is loaded and hooks are installed
        MessageBoxW(NULL, L"LookBlockNet DLL loaded and hooks installed.\nCheck for log file in app directory.", 
                   L"LookBlockNet", MB_OK | MB_ICONINFORMATION);
    } else if (r == DLL_PROCESS_DETACH) {
        DeleteCriticalSection(&g_mapLock);
    }
    return TRUE;
}


