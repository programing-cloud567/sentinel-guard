#include "sg_runtime.hpp"
#include "sg_scanner.h"

#include <array>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {
std::wstring join_path(const std::wstring &directory, const std::wstring &name) {
    return (std::filesystem::path(directory) / name).wstring();
}
}

int sg_run_monitor(const std::wstring &directory, const std::wstring &database_path,
                   HANDLE stop_event) {
    HANDLE watcher = CreateFileW(directory.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (watcher == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Cannot watch folder (error " << GetLastError() << L"): "
                   << directory << L'\n';
        return 1;
    }

    std::wcout << L"Monitoring changes under: " << directory << L"\n"
               << L"Watcher detects files after they are written; it does not block execution.\n";

    std::array<BYTE, 64 * 1024> buffer{};
    OVERLAPPED overlapped{};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (overlapped.hEvent == nullptr) {
        CloseHandle(watcher);
        return 1;
    }

    int exit_code = 0;
    bool running = true;
    while (running) {
        ResetEvent(overlapped.hEvent);
        DWORD ignored = 0;
        const BOOL request = ReadDirectoryChangesW(
            watcher, buffer.data(), static_cast<DWORD>(buffer.size()), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION,
            &ignored, &overlapped, nullptr);
        if (!request && GetLastError() != ERROR_IO_PENDING) {
            std::wcerr << L"Directory watch failed (error " << GetLastError() << L").\n";
            exit_code = 1;
            break;
        }

        HANDLE waits[2] = {overlapped.hEvent, stop_event};
        const DWORD wait_count = stop_event == nullptr ? 1 : 2;
        const DWORD wait_result = WaitForMultipleObjects(wait_count, waits, FALSE, INFINITE);
        if (stop_event != nullptr && wait_result == WAIT_OBJECT_0 + 1) {
            CancelIoEx(watcher, &overlapped);
            break;
        }
        if (wait_result != WAIT_OBJECT_0) {
            std::wcerr << L"Directory watch wait failed.\n";
            exit_code = 1;
            break;
        }

        DWORD bytes = 0;
        if (!GetOverlappedResult(watcher, &overlapped, &bytes, FALSE)) {
            const DWORD error = GetLastError();
            if (error == ERROR_OPERATION_ABORTED) break;
            std::wcerr << L"Could not read directory changes (error " << error << L").\n";
            exit_code = 1;
            break;
        }

        auto *change = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(buffer.data());
        for (;;) {
            const std::wstring filename(change->FileName,
                change->FileNameLength / sizeof(wchar_t));
            if (change->Action == FILE_ACTION_ADDED ||
                change->Action == FILE_ACTION_MODIFIED ||
                change->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                const auto path = join_path(directory, filename);
                SGScanResult result{};
                const int status = sg_scan_file(path.c_str(), database_path.c_str(), &result);
                if (status == 0 && result.detected) {
                    std::wcout << L"[ALERT] score=" << result.score << L" rule="
                               << result.rule << L" file=" << path << L'\n';
                    const std::wstring message = L"SentinelGuard static signal: " + path + L"\n";
                    OutputDebugStringW(message.c_str());
                }
            }
            if (change->NextEntryOffset == 0) break;
            change = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(
                reinterpret_cast<BYTE *>(change) + change->NextEntryOffset);
        }
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(watcher);
    return exit_code;
}
