// TimeInjector: version.dll proxy skeleton
// - Loads first as version.dll in app directory
// - Runs our initialization (reads timer.config / timer.json)
// - Exports are forwarded via exports.def to the real system DLLs
// - In later steps we'll add API hooks to virtualize time

#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <algorithm>
#include <cctype>
// Detours for reliable API hooking (workflow supplies include path)
#include "detours.h"

// Minimal, dependency-free logging and config parsing scaffolding

namespace timeinject {

static wchar_t g_moduleDirectory[MAX_PATH] = {0};
static wchar_t g_logPath[MAX_PATH] = {0};
static wchar_t g_configPathIni[MAX_PATH] = {0};
static wchar_t g_configPathJson[MAX_PATH] = {0};

// Configuration options
struct Config {
	// Immediate_Mode: when true, install hooks immediately at process start
	bool immediateModeEnabled;
	// Moving_Mode: "progressive" => true, "static" => false
	bool progressiveMode;
	// Custom_Date_Time: ISO-like string in local time, e.g., 2025-10-09T00:00:00
	wchar_t customDateTime[64];
    // Master_Switch: global enable/disable for fake time
    bool masterSwitch;
    // Logging controls
    bool processLogEnabled;     // Process_log
    bool persistentLogEnabled;  // Presistant_log (append across runs)
};

static Config g_config = { /*immediateModeEnabled*/true, /*progressiveMode*/true, L"", /*masterSwitch*/true, /*processLogEnabled*/false, /*persistentLogEnabled*/false };

static bool g_logSessionInitialized = false;

static void writeLog(const wchar_t* fmt, ...)
{
	if (!g_config.processLogEnabled) return; // logging disabled by config

	DWORD createDisp = OPEN_ALWAYS;
	if (!g_logSessionInitialized && !g_config.persistentLogEnabled) {
		createDisp = CREATE_ALWAYS; // truncate on first write of this run
	}
	HANDLE h = CreateFileW(g_logPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
		createDisp, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) return;
	if (createDisp == OPEN_ALWAYS) {
		SetFilePointer(h, 0, nullptr, FILE_END);
	}

	wchar_t buffer[1024];
	va_list args;
	va_start(args, fmt);
	_vsnwprintf(buffer, sizeof(buffer) / sizeof(buffer[0]) - 2, fmt, args);
	va_end(args);
	wcscat_s(buffer, L"\r\n");

	DWORD bytes = 0;
	WriteFile(h, buffer, (DWORD)(wcslen(buffer) * sizeof(wchar_t)), &bytes, nullptr);
	CloseHandle(h);
	g_logSessionInitialized = true;
}

static bool fileExists(const wchar_t* path)
{
	DWORD attrs = GetFileAttributesW(path);
	return (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

// Very small INI-like parser: key=value per line
static void getCurrentLocalIso(wchar_t* outBuf, size_t outCount)
{
	SYSTEMTIME st{};
	GetLocalTime(&st);
	swprintf(outBuf, outCount, L"%04u-%02u-%02uT%02u:%02u:%02u",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
}

static void writeDefaultConfig()
{
	wchar_t nowIso[64] = {0};
	getCurrentLocalIso(nowIso, _countof(nowIso));

	// Compose ANSI text for simple INI
	char header[] =
		"# TimeInjector configuration (simple INI-style)\r\n"
		"# Master_Switch: true/false or 1/0 (global enable)\r\n"
		"# Custom_Date_Time: YYYY-MM-DDThh:mm:ss (local time)\r\n"
		"# Immediate_Mode: true/false or 1/0 (install hooks at start)\r\n"
		"# Moving_Mode: progressive | static or 1/0. (1=progressive | 0=static)\r\n\r\n";
    char body[1024];
	// Convert nowIso (wide) to UTF-8
	char nowUtf8[64] = {0};
	int n = WideCharToMultiByte(CP_UTF8, 0, nowIso, -1, nowUtf8, (int)sizeof(nowUtf8), nullptr, nullptr);
	if (n <= 0) {
		// fallback: empty
		strcpy_s(nowUtf8, "");
	}
    snprintf(body, sizeof(body),
        "Master_Switch = true\r\nCustom_Date_Time = %s\r\nImmediate_Mode = true\r\nMoving_Mode = progressive\r\n"
        "Process_log = false\r\nPresistant_log = false\r\n\r\n"
        "# Process_log: when false/0 no timeinject.log is created; when true/1 logs are written.\r\n"
        "# Presistant_log: when false/0 each run overwrites the log (no append); when true/1 logs append across runs.\r\n",
        nowUtf8);

	HANDLE h = CreateFileW(g_configPathIni, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		writeLog(L"[TimeInjector] Failed to create default timer.config: %lu", GetLastError());
		return;
	}
	DWORD written = 0;
	WriteFile(h, header, (DWORD)strlen(header), &written, nullptr);
	WriteFile(h, body, (DWORD)strlen(body), &written, nullptr);
	CloseHandle(h);
	writeLog(L"[TimeInjector] Created default timer.config with current time %s", nowIso);

	// Update in-memory defaults
	wcscpy_s(g_config.customDateTime, nowIso);
	g_config.immediateModeEnabled = true;
	g_config.progressiveMode = true;
	g_config.masterSwitch = true;
}

static void loadConfigIni()
{
	HANDLE h = CreateFileW(g_configPathIni, GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) {
		writeLog(L"[TimeInjector] timer.config not found; creating one");
		writeDefaultConfig();
		return;
	}

	char buf[4096];
	DWORD read = 0;
	if (!ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr)) {
		CloseHandle(h);
		return;
	}
	CloseHandle(h);
	buf[read] = '\0';

	// naive parse (ASCII assumed)
	const char* p = buf;
	while (*p) {
		// extract line
		const char* lineStart = p;
		while (*p && *p != '\n' && *p != '\r') p++;
		std::string line(lineStart, p - lineStart);
		while (*p == '\r' || *p == '\n') p++;

		// trim spaces
		auto ltrim = [](std::string& s){ s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char c){return !isspace(c);})); };
		auto rtrim = [](std::string& s){ s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char c){return !isspace(c);}).base(), s.end()); };
		ltrim(line); rtrim(line);
		if (line.empty() || line[0] == '#') continue;
		size_t eq = line.find('=');
		if (eq == std::string::npos) continue;
		std::string key = line.substr(0, eq);
		std::string val = line.substr(eq + 1);
		ltrim(key); rtrim(key); ltrim(val); rtrim(val);

		// to lower helper
    auto lower = [](std::string s){ for (auto& c: s) c = (char)tolower((unsigned char)c); return s; };
    auto parseBool = [&](const std::string& s)->bool {
        std::string v = lower(s);
        return (v == "1" || v == "true" || v == "yes");
    };
		std::string k = lower(key);
		std::string v = lower(val);

		if (k == "master_switch") {
			g_config.masterSwitch = parseBool(v);
		} else if (k == "immediate_mode" || k == "enabled") { // support legacy key
			g_config.immediateModeEnabled = parseBool(v);
		} else if (k == "moving_mode" || k == "mode") { // support legacy key
			if (v == "progressive" || v == "1" || v == "true") {
				g_config.progressiveMode = true;
			} else if (v == "static" || v == "0" || v == "false") {
				g_config.progressiveMode = false;
			}
		} else if (k == "custom_date_time" || k == "start_datetime") { // support legacy key
			// store wide
			int wlen = MultiByteToWideChar(CP_UTF8, 0, val.c_str(), (int)val.size(), nullptr, 0);
			if (wlen > 0 && wlen < (int)(sizeof(g_config.customDateTime) / sizeof(wchar_t))) {
				MultiByteToWideChar(CP_UTF8, 0, val.c_str(), (int)val.size(), g_config.customDateTime, wlen);
				g_config.customDateTime[wlen] = L'\0';
			}
		} else if (k == "process_log") {
			g_config.processLogEnabled = parseBool(v);
		} else if (k == "presistant_log") {
			g_config.persistentLogEnabled = parseBool(v);
		}
	}

	writeLog(L"[TimeInjector] Config loaded: Master_Switch=%d, Immediate_Mode=%d, Moving_Mode=%s, Custom_Date_Time=%s",
		g_config.masterSwitch ? 1 : 0,
		g_config.immediateModeEnabled ? 1 : 0,
		g_config.progressiveMode ? L"progressive" : L"static",
		g_config.customDateTime);
}

static void initializePaths(HMODULE hModule)
{
	GetModuleFileNameW(hModule, g_moduleDirectory, MAX_PATH);
	PathRemoveFileSpecW(g_moduleDirectory);

	wcscpy_s(g_logPath, g_moduleDirectory);
	PathAppendW(g_logPath, L"timeinject.log");

	wcscpy_s(g_configPathIni, g_moduleDirectory);
	PathAppendW(g_configPathIni, L"timer.config");

	wcscpy_s(g_configPathJson, g_moduleDirectory);
	PathAppendW(g_configPathJson, L"timer.json");
}

static void loadConfiguration()
{
	if (fileExists(g_configPathIni)) {
		loadConfigIni();
		return;
	}
	// If missing, create default immediately so even short-lived loads persist config
	writeLog(L"[TimeInjector] timer.config missing; creating default config");
	writeDefaultConfig();
	return;
}

// Placeholder for future: install API hooks based on g_config
static void installTimeHooksIfEnabled()
{
	if (!g_config.masterSwitch) {
		writeLog(L"[TimeInjector] Master_Switch=false; forwarding real time");
		return;
	}
	if (!g_config.immediateModeEnabled) {
		writeLog(L"[TimeInjector] Immediate_Mode=false; skipping early hook install");
		return;
	}
	writeLog(L"[TimeInjector] Installing time hooks...");
}

} // namespace timeinject

// ===== Real version.dll loader and export resolution (x86) =====
static HMODULE g_realVersion = NULL;

// Pointers to real exports
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

static void load_real_version_and_resolve()
{
	if (g_realVersion)
		return;

	wchar_t sysdir[MAX_PATH];
	if (GetSystemDirectoryW(sysdir, MAX_PATH) == 0) {
		timeinject::writeLog(L"[TimeInjector] GetSystemDirectoryW failed: %lu", GetLastError());
		return;
	}
	wchar_t realPath[MAX_PATH];
	wcscpy_s(realPath, sysdir);
	PathAppendW(realPath, L"version.dll");

	g_realVersion = LoadLibraryW(realPath);
	if (!g_realVersion) {
		timeinject::writeLog(L"[TimeInjector] LoadLibraryW(%s) failed: %lu", realPath, GetLastError());
		return;
	}

	// Resolve all exports by name
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
		if (!*(it.slot)) {
			timeinject::writeLog(L"[TimeInjector] GetProcAddress failed for %S", it.name);
		}
	}
}

#if defined(_M_IX86)
// x86 naked jump thunks to preserve unknown signatures exactly (prefixed to avoid name clashes)
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
// x64 typed forwarders using real prototypes from winver.h
extern "C" BOOL WINAPI TI_GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    auto f = (decltype(&GetFileVersionInfoA))p_GetFileVersionInfoA; return f(lptstrFilename, dwHandle, dwLen, lpData);
}
extern "C" BOOL WINAPI TI_GetFileVersionInfoByHandle(HANDLE hFile, LPVOID lpReserved) {
    auto f = (BOOL (WINAPI*)(HANDLE, LPVOID))p_GetFileVersionInfoByHandle; return f(hFile, lpReserved);
}
extern "C" BOOL WINAPI TI_GetFileVersionInfoExA(DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    auto f = (decltype(&GetFileVersionInfoExA))p_GetFileVersionInfoExA; return f(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}
extern "C" BOOL WINAPI TI_GetFileVersionInfoExW(DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    auto f = (decltype(&GetFileVersionInfoExW))p_GetFileVersionInfoExW; return f(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData);
}
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle) {
    auto f = (decltype(&GetFileVersionInfoSizeA))p_GetFileVersionInfoSizeA; return f(lptstrFilename, lpdwHandle);
}
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeExA(DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle) {
    auto f = (decltype(&GetFileVersionInfoSizeExA))p_GetFileVersionInfoSizeExA; return f(dwFlags, lpwstrFilename, lpdwHandle);
}
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeExW(DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle) {
    auto f = (decltype(&GetFileVersionInfoSizeExW))p_GetFileVersionInfoSizeExW; return f(dwFlags, lpwstrFilename, lpdwHandle);
}
extern "C" DWORD WINAPI TI_GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    auto f = (decltype(&GetFileVersionInfoSizeW))p_GetFileVersionInfoSizeW; return f(lptstrFilename, lpdwHandle);
}
extern "C" BOOL WINAPI TI_GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData) {
    auto f = (decltype(&GetFileVersionInfoW))p_GetFileVersionInfoW; return f(lptstrFilename, dwHandle, dwLen, lpData);
}
extern "C" DWORD WINAPI TI_VerFindFileA(DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPSTR szAppDir, LPSTR szCurDir, PUINT lpuCurDirLen, LPSTR szDestDir, PUINT lpuDestDirLen) {
    auto f = (decltype(&VerFindFileA))p_VerFindFileA; return f(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen);
}
extern "C" DWORD WINAPI TI_VerFindFileW(DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPWSTR szAppDir, LPWSTR szCurDir, PUINT lpuCurDirLen, LPWSTR szDestDir, PUINT lpuDestDirLen) {
    auto f = (decltype(&VerFindFileW))p_VerFindFileW; return f(uFlags, szFileName, szWinDir, szAppDir, szCurDir, lpuCurDirLen, szDestDir, lpuDestDirLen);
}
extern "C" DWORD WINAPI TI_VerInstallFileA(DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir, LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT lpuTmpFileLen) {
    auto f = (decltype(&VerInstallFileA))p_VerInstallFileA; return f(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, lpuTmpFileLen);
}
extern "C" DWORD WINAPI TI_VerInstallFileW(DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName, LPCWSTR szSrcDir, LPCWSTR szDestDir, LPCWSTR szCurDir, LPWSTR szTmpFile, PUINT lpuTmpFileLen) {
    auto f = (decltype(&VerInstallFileW))p_VerInstallFileW; return f(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, lpuTmpFileLen);
}
extern "C" DWORD WINAPI TI_VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD cchLang) {
    auto f = (decltype(&VerLanguageNameA))p_VerLanguageNameA; return f(wLang, szLang, cchLang);
}
extern "C" DWORD WINAPI TI_VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD cchLang) {
    auto f = (decltype(&VerLanguageNameW))p_VerLanguageNameW; return f(wLang, szLang, cchLang);
}
extern "C" BOOL WINAPI TI_VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    auto f = (decltype(&VerQueryValueA))p_VerQueryValueA; return f(pBlock, lpSubBlock, lplpBuffer, puLen);
}
extern "C" BOOL WINAPI TI_VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen) {
    auto f = (decltype(&VerQueryValueW))p_VerQueryValueW; return f(pBlock, lpSubBlock, lplpBuffer, puLen);
}
#endif

// ===== Time virtualization hooks =====
// Original pointers
typedef VOID (WINAPI *PFN_GetSystemTime)(LPSYSTEMTIME);
typedef VOID (WINAPI *PFN_GetLocalTime)(LPSYSTEMTIME);
typedef VOID (WINAPI *PFN_GetSystemTimeAsFileTime)(LPFILETIME);
typedef VOID (WINAPI *PFN_GetSystemTimePreciseAsFileTime)(LPFILETIME);
typedef LONG (NTAPI *PFN_NtQuerySystemTime)(PLARGE_INTEGER);

static PFN_GetSystemTime p_GetSystemTime_Orig = nullptr;
static PFN_GetLocalTime p_GetLocalTime_Orig = nullptr;
static PFN_GetSystemTimeAsFileTime p_GetSystemTimeAsFileTime_Orig = nullptr;
static PFN_GetSystemTimePreciseAsFileTime p_GetSystemTimePreciseAsFileTime_Orig = nullptr;
static PFN_NtQuerySystemTime p_NtQuerySystemTime_Orig = nullptr;

// Baselines
static FILETIME g_baseRealFileTime = {0};
static FILETIME g_baseFakeFileTime = {0};
static bool g_timeBaseInitialized = false;

static bool parseIsoLocalToSystemTime(const wchar_t* iso, SYSTEMTIME* outLocal)
{
	if (!iso || !*iso) return false;
	unsigned y=0,m=0,d=0,hh=0,mm=0,ss=0;
	int n = swscanf(iso, L"%u-%u-%uT%u:%u:%u", &y,&m,&d,&hh,&mm,&ss);
	if (n < 3) return false;
	SYSTEMTIME st{};
	st.wYear = (WORD)y; st.wMonth=(WORD)m; st.wDay=(WORD)d;
	st.wHour=(WORD)hh; st.wMinute=(WORD)mm; st.wSecond=(WORD)ss; st.wMilliseconds=0;
	*outLocal = st;
	return true;
}

static void ensureTimeBase()
{
	if (g_timeBaseInitialized) return;
	// Establish base real time (UTC)
	if (!p_GetSystemTimeAsFileTime_Orig) {
		// Fallback to kernel32 export if precise pointer missing
		FILETIME ft{}; ::GetSystemTimeAsFileTime(&ft); g_baseRealFileTime = ft;
	} else {
		p_GetSystemTimeAsFileTime_Orig(&g_baseRealFileTime);
	}
	// Determine base fake time from config (Custom_Date_Time is local time)
	SYSTEMTIME localSt{};
	if (!timeinject::g_config.customDateTime[0] || !parseIsoLocalToSystemTime(timeinject::g_config.customDateTime, &localSt)) {
		// If missing or unparsable, use current local time
		GetLocalTime(&localSt);
	}
	SYSTEMTIME utcSt{};
	TzSpecificLocalTimeToSystemTime(nullptr, &localSt, &utcSt);
	FILETIME ftUtc{};
	SystemTimeToFileTime(&utcSt, &ftUtc);
	g_baseFakeFileTime = ftUtc;
	g_timeBaseInitialized = true;
}

static void computeFakeUtcFileTime(FILETIME* outNowUtc)
{
	ensureTimeBase();
	FILETIME realNow{};
	if (p_GetSystemTimeAsFileTime_Orig) {
		p_GetSystemTimeAsFileTime_Orig(&realNow);
	} else {
		::GetSystemTimeAsFileTime(&realNow);
	}
	ULARGE_INTEGER r0{}, r1{}, f0{};
	r0.LowPart = g_baseRealFileTime.dwLowDateTime; r0.HighPart = g_baseRealFileTime.dwHighDateTime;
	r1.LowPart = realNow.dwLowDateTime; r1.HighPart = realNow.dwHighDateTime;
	f0.LowPart = g_baseFakeFileTime.dwLowDateTime; f0.HighPart = g_baseFakeFileTime.dwHighDateTime;
	ULARGE_INTEGER out{};
	if (timeinject::g_config.progressiveMode) {
		out.QuadPart = f0.QuadPart + (r1.QuadPart - r0.QuadPart);
	} else {
		out.QuadPart = f0.QuadPart; // static
	}
	outNowUtc->dwLowDateTime = out.LowPart;
	outNowUtc->dwHighDateTime = out.HighPart;
}

// Hooked implementations
static VOID WINAPI Hook_GetSystemTime(LPSYSTEMTIME lpSystemTime)
{
	if (!timeinject::g_config.masterSwitch) return p_GetSystemTime_Orig(lpSystemTime);
	FILETIME ft{}; computeFakeUtcFileTime(&ft);
	FileTimeToSystemTime(&ft, lpSystemTime);
}

static VOID WINAPI Hook_GetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	if (!timeinject::g_config.masterSwitch) return p_GetLocalTime_Orig(lpSystemTime);
	FILETIME ftUtc{}; computeFakeUtcFileTime(&ftUtc);
	FILETIME ftLocal{};
	FileTimeToLocalFileTime(&ftUtc, &ftLocal);
	FileTimeToSystemTime(&ftLocal, lpSystemTime);
}

static VOID WINAPI Hook_GetSystemTimeAsFileTime(LPFILETIME lpFileTime)
{
	if (!timeinject::g_config.masterSwitch) return p_GetSystemTimeAsFileTime_Orig(lpFileTime);
	computeFakeUtcFileTime(lpFileTime);
}

static VOID WINAPI Hook_GetSystemTimePreciseAsFileTime(LPFILETIME lpFileTime)
{
	if (!timeinject::g_config.masterSwitch) {
		if (p_GetSystemTimePreciseAsFileTime_Orig) return p_GetSystemTimePreciseAsFileTime_Orig(lpFileTime);
		return p_GetSystemTimeAsFileTime_Orig(lpFileTime);
	}
	computeFakeUtcFileTime(lpFileTime);
}

static LONG NTAPI Hook_NtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
	if (!timeinject::g_config.masterSwitch) return p_NtQuerySystemTime_Orig(SystemTime);
	FILETIME ft{}; computeFakeUtcFileTime(&ft);
	SystemTime->LowPart = ft.dwLowDateTime;
	SystemTime->HighPart = ft.dwHighDateTime;
	return 0; // STATUS_SUCCESS
}

static void install_time_hooks()
{
	HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
	HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
	if (hK32) {
		p_GetSystemTime_Orig = (PFN_GetSystemTime)GetProcAddress(hK32, "GetSystemTime");
		p_GetLocalTime_Orig = (PFN_GetLocalTime)GetProcAddress(hK32, "GetLocalTime");
		p_GetSystemTimeAsFileTime_Orig = (PFN_GetSystemTimeAsFileTime)GetProcAddress(hK32, "GetSystemTimeAsFileTime");
		p_GetSystemTimePreciseAsFileTime_Orig = (PFN_GetSystemTimePreciseAsFileTime)GetProcAddress(hK32, "GetSystemTimePreciseAsFileTime");
	}
	if (hNt) {
		p_NtQuerySystemTime_Orig = (PFN_NtQuerySystemTime)GetProcAddress(hNt, "NtQuerySystemTime");
	}

	LONG detErr = NO_ERROR;
	DetourRestoreAfterWith();
	if (DetourTransactionBegin() != NO_ERROR) { timeinject::writeLog(L"[TimeInjector] DetourTransactionBegin failed"); return; }
	DetourUpdateThread(GetCurrentThread());
	if (p_GetSystemTime_Orig) detErr = DetourAttach(&(PVOID&)p_GetSystemTime_Orig, Hook_GetSystemTime);
	if (p_GetLocalTime_Orig) detErr = DetourAttach(&(PVOID&)p_GetLocalTime_Orig, Hook_GetLocalTime);
	if (p_GetSystemTimeAsFileTime_Orig) detErr = DetourAttach(&(PVOID&)p_GetSystemTimeAsFileTime_Orig, Hook_GetSystemTimeAsFileTime);
	if (p_GetSystemTimePreciseAsFileTime_Orig) detErr = DetourAttach(&(PVOID&)p_GetSystemTimePreciseAsFileTime_Orig, Hook_GetSystemTimePreciseAsFileTime);
	if (p_NtQuerySystemTime_Orig) detErr = DetourAttach(&(PVOID&)p_NtQuerySystemTime_Orig, Hook_NtQuerySystemTime);
	if (DetourTransactionCommit() != NO_ERROR) {
		timeinject::writeLog(L"[TimeInjector] DetourTransactionCommit failed (%ld)", detErr);
		return;
	}
	ensureTimeBase();
	timeinject::writeLog(L"[TimeInjector] Time hooks installed (progressive=%d)", timeinject::g_config.progressiveMode ? 1 : 0);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH) {
		timeinject::initializePaths(hinstDLL);
		timeinject::writeLog(L"[TimeInjector] version.dll proxy loaded");
		timeinject::loadConfiguration();
		load_real_version_and_resolve();
		timeinject::installTimeHooksIfEnabled();
		// Install if enabled
		if (timeinject::g_config.masterSwitch && timeinject::g_config.immediateModeEnabled) {
			install_time_hooks();
		}
	}
	return TRUE;
}


