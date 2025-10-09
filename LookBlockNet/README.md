# LookBlockNet (version.dll + lookblocknet.dll)

## Overview
- `version.dll` (proxy): Loads `lookblocknet.dll` from the same directory, then forwards all 17 exports to the real system `version.dll`.
- `lookblocknet.dll`: Your custom payload. In v1 this is a blueprint (no-op). Later you can add network-blocking logic.

## How it works
1. App loads `version.dll` from its folder → our proxy is loaded first.
2. Proxy loads `lookblocknet.dll` (if present) for your custom logic.
3. Proxy loads `%SystemRoot%\System32\version.dll` and forwards all exports so the app behaves normally.

## Build (GitHub Actions)
Workflows are under `LookBlockNet/.github/workflows/`:
- `build-lookblocknet-x86.yml`: builds 32-bit `version.dll` and `lookblocknet.dll`.
- `build-lookblocknet-x64.yml`: builds 64-bit `version.dll` and `lookblocknet.dll`.
Both workflows fetch and build Detours 4.0.1 and link against it.

## Outputs
- `LookBlockNet/version/version.dll` (proxy)
- `LookBlockNet/lookblocknet/lookblocknet.dll` (payload)

## Usage
1. Place both DLLs in the target application's directory.
2. Run the application; your `lookblocknet.dll` will load automatically.
3. Implement your logic inside `lookblocknet.cpp` as needed (e.g., hooking WinHTTP/WinINet/WS2_32).


