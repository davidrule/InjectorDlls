// TimeInjector (version.dll proxy)

## What it does
- Loads first as `version.dll` from the app folder and forwards all 17 exports to the real system `version.dll`.
- Installs time hooks (if enabled) to virtualize process time:
  - GetSystemTime, GetLocalTime
  - GetSystemTimeAsFileTime, GetSystemTimePreciseAsFileTime
  - NtQuerySystemTime
- Supports two modes:
  - Progressive: fake time advances in sync with real time from a configured start.
  - Static: fake time remains fixed at the configured start.

## Configuration (timer.config)
The DLL auto-creates `timer.config` next to itself if missing, with current local time. Keys:

```
# TimeInjector configuration (simple INI-style)
# Master_Switch: true/false or 1/0 (global enable)
# Custom_Date_Time: ISO-like string in local time, e.g., 2025-10-09T00:00:00
# Immediate_Mode: true/false or 1/0 (install hooks at start)
# Moving_Mode: progressive | static or 1/0. (1=progressive | 0=static)

Master_Switch = true
Custom_Date_Time = 2025-10-09T00:00:00
Immediate_Mode = true
Moving_Mode = progressive
```

Notes:
- If `Custom_Date_Time` is present, it is always used (local time). Otherwise, the first-run current time is written and used.
- `Moving_Mode=1` equals `progressive`, `0` equals `static`.

## How the proxy works
- On load, the DLL resolves all real `version.dll` exports from `%SystemRoot%\System32\version.dll`.
- Each exported function is a thin jump to the real one (x86). Your app behavior remains unchanged, except for time APIs if enabled.

## Build
- GitHub Actions workflow `.github/workflows/build-timeinject.yml` builds x86 DLL with MSVC and Detours.
- Output files:
  - `version.dll` (place in target app folder)
  - `timer.config` (auto-created/used next to DLL)

## Usage
1. Place `version.dll` (this project output) into the target application's directory.
2. Adjust `timer.config` as needed.
3. Start the application. Check `timeinject.log` for activity.
