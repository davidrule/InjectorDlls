// LookBlockNet: version.dll proxy that loads lookblocknet.dll then forwards to system version.dll

#include <windows.h>
#include <shlwapi.h>

static HMODULE g_realVersion = NULL;
static HMODULE g_lookBlockNet = NULL;

// real exports
static FARPROC p_GetFileVersionInfoA = NULL;
static FARPROC p_GetFileVersionInfoByHandle = NULL;
static FARPROC p_GetFileVersionInfoExA = NULL;
static FARPROC p_GetFileVersionInfoExW = NULL;
static FARPROC p_GetFileVersionInfoSizeA = NULL;
static FARPROC p_GetFileVersionInfoSizeExA = NULL;
static FARPROC p_GetFileVersionInfoSizeExW = NULL;
static FARPROC p_GetFileVersionInfoSizeW = NULL;
static FARPROC p_GetFileVersionInfoW = NULL;
static FARPROC p_VerFindFileA = NULL;
static FARPROC p_VerFindFileW = NULL;
static FARPROC p_VerInstallFileA = NULL;
static FARPROC p_VerInstallFileW = NULL;
static FARPROC p_VerLanguageNameA = NULL;
static FARPROC p_VerLanguageNameW = NULL;
static FARPROC p_VerQueryValueA = NULL;
static FARPROC p_VerQueryValueW = NULL;

static void load_real_version_and_plugins(HMODULE self)
{
    // Load system version.dll
    wchar_t sysdir[MAX_PATH];
    if (GetSystemDirectoryW(sysdir, MAX_PATH)) {
        wchar_t realPath[MAX_PATH];
        wcscpy_s(realPath, sysdir);
        PathAppendW(realPath, L"version.dll");
        g_realVersion = LoadLibraryW(realPath);
    }

    if (!g_realVersion) return;

    struct NamePtr { const char* name; FARPROC* slot; } items[] = {
        {"GetFileVersionInfoA", &p_GetFileVersionInfoA},
        {"GetFileVersionInfoByHandle", &p_GetFileVersionInfoByHandle},
        {"GetFileVersionInfoExA", &p_GetFileVersionInfoExA},
        {"GetFileVersionInfoExW", &p_GetFileVersionInfoExW},
        {"GetFileVersionInfoSizeA", &p_GetFileVersionInfoSizeA},
        {"GetFileVersionInfoSizeExA", &p_GetFileVersionInfoSizeExA},
        {"GetFileVersionInfoSizeExW", &p_GetFileVersionInfoSizeExW},
        {"GetFileVersionInfoSizeW", &p_GetFileVersionInfoSizeW},
        {"GetFileVersionInfoW", &p_GetFileVersionInfoW},
        {"VerFindFileA", &p_VerFindFileA},
        {"VerFindFileW", &p_VerFindFileW},
        {"VerInstallFileA", &p_VerInstallFileA},
        {"VerInstallFileW", &p_VerInstallFileW},
        {"VerLanguageNameA", &p_VerLanguageNameA},
        {"VerLanguageNameW", &p_VerLanguageNameW},
        {"VerQueryValueA", &p_VerQueryValueA},
        {"VerQueryValueW", &p_VerQueryValueW},
    };
    for (const auto& it : items) {
        *(it.slot) = GetProcAddress(g_realVersion, it.name);
    }
}

static DWORD WINAPI load_lookblocknet_async(LPVOID mod)
{
    HMODULE self = (HMODULE)mod;
    wchar_t dir[MAX_PATH];
    if (GetModuleFileNameW(self, dir, MAX_PATH)) {
        PathRemoveFileSpecW(dir);
        wchar_t pluginPath[MAX_PATH];
        wcscpy_s(pluginPath, dir);
        PathAppendW(pluginPath, L"lookblocknet.dll");
        HMODULE h = LoadLibraryW(pluginPath);
        g_lookBlockNet = h;
        if (!h) {
            wchar_t msg[260];
            wsprintfW(msg, L"LookBlockNet: LoadLibrary failed (%lu) for %s", GetLastError(), pluginPath);
            OutputDebugStringW(msg);
        }
    }
    return 0;
}

#if defined(_M_IX86)
extern "C" __declspec(naked) void TI_GetFileVersionInfoA() { __asm { jmp dword ptr [p_GetFileVersionInfoA] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoByHandle() { __asm { jmp dword ptr [p_GetFileVersionInfoByHandle] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoExA() { __asm { jmp dword ptr [p_GetFileVersionInfoExA] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoExW() { __asm { jmp dword ptr [p_GetFileVersionInfoExW] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoSizeA() { __asm { jmp dword ptr [p_GetFileVersionInfoSizeA] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoSizeExA() { __asm { jmp dword ptr [p_GetFileVersionInfoSizeExA] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoSizeExW() { __asm { jmp dword ptr [p_GetFileVersionInfoSizeExW] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoSizeW() { __asm { jmp dword ptr [p_GetFileVersionInfoSizeW] } }
extern "C" __declspec(naked) void TI_GetFileVersionInfoW() { __asm { jmp dword ptr [p_GetFileVersionInfoW] } }
extern "C" __declspec(naked) void TI_VerFindFileA() { __asm { jmp dword ptr [p_VerFindFileA] } }
extern "C" __declspec(naked) void TI_VerFindFileW() { __asm { jmp dword ptr [p_VerFindFileW] } }
extern "C" __declspec(naked) void TI_VerInstallFileA() { __asm { jmp dword ptr [p_VerInstallFileA] } }
extern "C" __declspec(naked) void TI_VerInstallFileW() { __asm { jmp dword ptr [p_VerInstallFileW] } }
extern "C" __declspec(naked) void TI_VerLanguageNameA() { __asm { jmp dword ptr [p_VerLanguageNameA] } }
extern "C" __declspec(naked) void TI_VerLanguageNameW() { __asm { jmp dword ptr [p_VerLanguageNameW] } }
extern "C" __declspec(naked) void TI_VerQueryValueA() { __asm { jmp dword ptr [p_VerQueryValueA] } }
extern "C" __declspec(naked) void TI_VerQueryValueW() { __asm { jmp dword ptr [p_VerQueryValueW] } }
#else
#include <winver.h>
extern "C" BOOL WINAPI TI_GetFileVersionInfoA(LPCSTR a,DWORD b,DWORD c,LPVOID d){auto f=(decltype(&GetFileVersionInfoA))p_GetFileVersionInfoA;return f(a,b,c,d);} 
extern "C" BOOL WINAPI TI_GetFileVersionInfoByHandle(HANDLE h,LPVOID r){auto f=(BOOL (WINAPI*)(HANDLE,LPVOID))p_GetFileVersionInfoByHandle;return f(h,r);} 
extern "C" BOOL WINAPI TI_GetFileVersionInfoExA(DWORD f1,LPCSTR f2,DWORD f3,DWORD f4,LPVOID f5){auto f=(decltype(&GetFileVersionInfoExA))p_GetFileVersionInfoExA;return f(f1,f2,f3,f4,f5);} 
extern "C" BOOL WINAPI TI_GetFileVersionInfoExW(DWORD f1,LPCWSTR f2,DWORD f3,DWORD f4,LPVOID f5){auto f=(decltype(&GetFileVersionInfoExW))p_GetFileVersionInfoExW;return f(f1,f2,f3,f4,f5);} 
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeA(LPCSTR a,LPDWORD b){auto f=(decltype(&GetFileVersionInfoSizeA))p_GetFileVersionInfoSizeA;return f(a,b);} 
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeExA(DWORD f1,LPCSTR f2,LPDWORD f3){auto f=(decltype(&GetFileVersionInfoSizeExA))p_GetFileVersionInfoSizeExA;return f(f1,f2,f3);} 
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeExW(DWORD f1,LPCWSTR f2,LPDWORD f3){auto f=(decltype(&GetFileVersionInfoSizeExW))p_GetFileVersionInfoSizeExW;return f(f1,f2,f3);} 
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeW(LPCWSTR a,LPDWORD b){auto f=(decltype(&GetFileVersionInfoSizeW))p_GetFileVersionInfoSizeW;return f(a,b);} 
extern "C" BOOL WINAPI TI_GetFileVersionInfoW(LPCWSTR a,DWORD b,DWORD c,LPVOID d){auto f=(decltype(&GetFileVersionInfoW))p_GetFileVersionInfoW;return f(a,b,c,d);} 
extern "C" DWORD WINAPI TI_VerFindFileA(DWORD u,LPCSTR a,LPCSTR b,LPSTR c,LPSTR d,PUINT e,LPSTR f,PUINT g){auto fn=(decltype(&VerFindFileA))p_VerFindFileA;return fn(u,a,b,c,d,e,f,g);} 
extern "C" DWORD WINAPI TI_VerFindFileW(DWORD u,LPCWSTR a,LPCWSTR b,LPWSTR c,LPWSTR d,PUINT e,LPWSTR f,PUINT g){auto fn=(decltype(&VerFindFileW))p_VerFindFileW;return fn(u,a,b,c,d,e,f,g);} 
extern "C" DWORD WINAPI TI_VerInstallFileA(DWORD u,LPCSTR a,LPCSTR b,LPCSTR c,LPCSTR d,LPCSTR e,LPSTR f,PUINT g){auto fn=(decltype(&VerInstallFileA))p_VerInstallFileA;return fn(u,a,b,c,d,e,f,g);} 
extern "C" DWORD WINAPI TI_VerInstallFileW(DWORD u,LPCWSTR a,LPCWSTR b,LPCWSTR c,LPCWSTR d,LPCWSTR e,LPWSTR f,PUINT g){auto fn=(decltype(&VerInstallFileW))p_VerInstallFileW;return fn(u,a,b,c,d,e,f,g);} 
extern "C" DWORD WINAPI TI_VerLanguageNameA(DWORD w,LPSTR s,DWORD c){auto fn=(decltype(&VerLanguageNameA))p_VerLanguageNameA;return fn(w,s,c);} 
extern "C" DWORD WINAPI TI_VerLanguageNameW(DWORD w,LPWSTR s,DWORD c){auto fn=(decltype(&VerLanguageNameW))p_VerLanguageNameW;return fn(w,s,c);} 
extern "C" BOOL WINAPI TI_VerQueryValueA(LPCVOID p,LPCSTR s,LPVOID *o,PUINT u){auto fn=(decltype(&VerQueryValueA))p_VerQueryValueA;return fn(p,s,o,u);} 
extern "C" BOOL WINAPI TI_VerQueryValueW(LPCVOID p,LPCWSTR s,LPVOID *o,PUINT u){auto fn=(decltype(&VerQueryValueW))p_VerQueryValueW;return fn(p,s,o,u);} 
#endif

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) {
        // Load the real system version.dll first
        load_real_version_and_plugins(h);

        // Build plugin path (same directory as this proxy)
        wchar_t dir[MAX_PATH];
        if (GetModuleFileNameW(h, dir, MAX_PATH)) {
            PathRemoveFileSpecW(dir);
            wchar_t pluginPath[MAX_PATH];
            wcscpy_s(pluginPath, dir);
            PathAppendW(pluginPath, L"lookblocknet.dll");

            // Prepare robust loading: prefer local dir for dependency search
            HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
            typedef BOOL (WINAPI *PFN_SetDefaultDllDirectories)(DWORD);
            typedef DLL_DIRECTORY_COOKIE (WINAPI *PFN_AddDllDirectory)(PCWSTR);
            typedef BOOL (WINAPI *PFN_RemoveDllDirectory)(DLL_DIRECTORY_COOKIE);
            PFN_SetDefaultDllDirectories pSetDefaultDllDirectories = hKernel ? (PFN_SetDefaultDllDirectories)GetProcAddress(hKernel, "SetDefaultDllDirectories") : nullptr;
            PFN_AddDllDirectory pAddDllDirectory = hKernel ? (PFN_AddDllDirectory)GetProcAddress(hKernel, "AddDllDirectory") : nullptr;
            PFN_RemoveDllDirectory pRemoveDllDirectory = hKernel ? (PFN_RemoveDllDirectory)GetProcAddress(hKernel, "RemoveDllDirectory") : nullptr;

            DLL_DIRECTORY_COOKIE cookie = 0;
            if (pSetDefaultDllDirectories) {
                pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
                if (pAddDllDirectory) cookie = pAddDllDirectory(dir);
            }

            // Attempt to load with altered search path
            g_lookBlockNet = LoadLibraryExW(pluginPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

            if (cookie && pRemoveDllDirectory) pRemoveDllDirectory(cookie);

            // Show definitive UI for debug
            wchar_t msg[600];
            if (!g_lookBlockNet) {
                DWORD err = GetLastError();
                wsprintfW(msg, L"LookBlockNet DEBUG\n\nFAILED to load:\n%s\n\nGetLastError = %lu", pluginPath, err);
                MessageBoxW(NULL, msg, L"version.dll proxy", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST | MB_SETFOREGROUND);
            } else {
                wsprintfW(msg, L"LookBlockNet DEBUG\n\nSUCCESS loading:\n%s", pluginPath);
                MessageBoxW(NULL, msg, L"version.dll proxy", MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL | MB_TOPMOST | MB_SETFOREGROUND);
            }
        }
    }
    return TRUE;
}

