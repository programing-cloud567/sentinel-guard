# SentinelGuard

SentinelGuard is a small, native Windows security prototype written in C and C++. It has its own SHA-256 scanner, a local hash-list format, basic static heuristics, a directory-change monitor, and an optional VirusTotal hash lookup. It does not invoke Microsoft Defender or another antivirus scanner.

## Important limits

This is **not a full commercial antivirus** and does not provide kernel-level pre-execution blocking. The directory watcher inspects a file after Windows reports it was created or changed, so a file could run before the scan finishes. It monitors only the directory selected by the user. A production endpoint protection product requires a signed and audited filesystem minifilter driver, safe update infrastructure, a maintained threat-intelligence source, extensive false-positive handling, and security review.

VirusTotal does not publish its complete detection database for bundling. SentinelGuard sends only a file's SHA-256 hash to VirusTotal's public API; it never uploads file contents. API access, quotas, and terms depend on the key and VirusTotal account. No API key is included in this repository.

The source is intentionally kept maintainable rather than padded to tens of millions of generated lines. Line count does not create protection; tested scanning behavior and trustworthy, maintained intelligence do.

## Build (Visual Studio 2022/2026 C++ tools)

From PowerShell in the repository directory:

```powershell
& $env:ComSpec /c 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul && cl /nologo /EHsc /std:c++17 /O2 /W4 /permissive- /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I include src\main.cpp src\scanner.c src\realtime.cpp src\virustotal.cpp src\service.cpp /Fe:SentinelGuard.exe /link bcrypt.lib winhttp.lib advapi32.lib'
```

Or use CMake with an MSVC developer environment:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Commands

```powershell
.\SentinelGuard.exe scan C:\Users\you\Downloads
.\SentinelGuard.exe scan C:\path\to\file.exe
.\SentinelGuard.exe scan-json C:\Users\you\Downloads
.\SentinelGuard.exe monitor C:\Users\you\Downloads
.\SentinelGuard.exe --self-test
```

`monitor` continues until Ctrl+C. It logs detections to the console/debug output and does not delete or quarantine files.

`scan-json` writes one JSON document to standard output, with a `results` entry for each scanned file or
error and aggregate `summary` counts. Non-ASCII paths are escaped as Unicode sequences, so the output
remains valid UTF-8/ASCII for redirected files and automation. Example result:

```json
{"schema_version":1,"results":[{"path":"C:\\sample.exe","status":"scanned","sha256":"...","detected":false,"score":0,"rule":""}],"summary":{"scanned":1,"detected":0,"unreadable":0}}
```

Keep standard error separate when redirecting JSON output; database warnings are written there.

To install the optional auto-starting Windows service, run an elevated terminal and select the one directory to monitor:

```powershell
.\SentinelGuard.exe install-service C:\Users\you\Downloads
.\SentinelGuard.exe uninstall-service
```

The service monitors that directory tree only. Installing it does not install a kernel driver or block file execution.

## Local SHA-256 list

The optional signature database is UTF-8 text with one `SHA256|label` pair per line. The included `signatures.txt` contains only the public EICAR test-file hash, not a malware collection. Add hashes only from sources you trust. To create an empty database:

```powershell
.\SentinelGuard.exe init-db C:\ProgramData\SentinelGuard\signatures.txt
.\SentinelGuard.exe scan C:\path\to\scan C:\ProgramData\SentinelGuard\signatures.txt
```

## VirusTotal hash lookup

Set your API key in the current PowerShell session; do not commit it:

```powershell
$env:SENTINELGUARD_VT_API_KEY = "your-personal-api-key"
.\SentinelGuard.exe vt C:\path\to\file.exe
```

The client calculates SHA-256 locally and queries `GET /api/v3/files/{sha256}` over HTTPS. A `404` means the hash has no report. A missing key, rate limit, network error, or API error is reported rather than treated as a clean result.

## Self-test

```powershell
.\SentinelGuard.exe --self-test
powershell -ExecutionPolicy Bypass -File tests\scan-json.ps1 -ExePath out\SentinelGuard.exe
```

The self-test verifies the built-in test signature in memory and does not write an antivirus test file to disk.
The PowerShell smoke test checks JSON parsing, Unicode file names, detection results, and exit codes.

`scan` and `scan-json` are script-friendly: they exit with `0` when no signals or read errors occur, `1`
when one or more signals are found and every file was scanned, and `2` if any files could not be read or
the scan path could not be traversed. A `2` means the scan was incomplete; inspect the summary and any
`[SIGNAL]` lines, or the JSON `results` and `summary`.
