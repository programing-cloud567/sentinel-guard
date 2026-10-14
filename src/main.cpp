#include "sg_runtime.hpp"
#include "sg_scanner.h"

#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {
HANDLE g_console_stop_event = nullptr;

BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT ||
        signal == CTRL_CLOSE_EVENT || signal == CTRL_SHUTDOWN_EVENT) {
        if (g_console_stop_event) SetEvent(g_console_stop_event);
        return TRUE;
    }
    return FALSE;
}

std::wstring default_database_path() {
    wchar_t program_data[MAX_PATH]{};
    const DWORD length = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
    if (length != 0 && length < MAX_PATH) {
        const auto shared_database =
            std::filesystem::path(program_data) / L"SentinelGuard" / L"signatures.txt";
        std::error_code error;
        if (std::filesystem::exists(shared_database, error) && !error) {
            return shared_database.wstring();
        }
    }
    wchar_t executable[MAX_PATH]{};
    const DWORD exe_length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    if (exe_length != 0 && exe_length < MAX_PATH) {
        return (std::filesystem::path(executable).parent_path() / L"signatures.txt").wstring();
    }
    return (std::filesystem::current_path() / L"signatures.txt").wstring();
}

int scan_target(const std::wstring &target, const std::wstring &database) {
    std::error_code error;
    const std::filesystem::path root(target);
    if (!std::filesystem::exists(root, error) || error) {
        std::wcerr << L"Path does not exist or cannot be accessed: " << target << L'\n';
        return 2;
    }
    error.clear();
    if (!std::filesystem::exists(database, error) || error) {
        std::wcerr << L"Warning: local hash database is unavailable: " << database
                   << L". Built-in static checks will still run.\n";
    }

    std::size_t scanned = 0;
    std::size_t skipped = 0;
    std::size_t detected = 0;
    const auto scan_one = [&](const std::filesystem::path &path) {
        SGScanResult result{};
        const int status = sg_scan_file(path.c_str(), database.c_str(), &result);
        if (status != 0) {
            ++skipped;
            return;
        }
        ++scanned;
        if (result.detected) {
            ++detected;
            std::wcout << L"[SIGNAL] score=" << result.score << L" rule=" << result.rule
                       << L" sha256=" << result.sha256 << L" file=" << path.wstring() << L'\n';
        }
    };

    if (std::filesystem::is_regular_file(root, error)) {
        scan_one(root);
    } else {
        std::filesystem::recursive_directory_iterator iterator(
            root, std::filesystem::directory_options::skip_permission_denied, error);
        const std::filesystem::recursive_directory_iterator end;
        while (!error && iterator != end) {
            std::error_code item_error;
            if (iterator->is_regular_file(item_error)) {
                scan_one(iterator->path());
            } else if (item_error) {
                ++skipped;
            }
            iterator.increment(error);
            if (error) {
                ++skipped;
                error.clear();
                iterator.increment(error);
            }
        }
    }

    std::wcout << L"Scan complete: " << scanned << L" file(s), " << detected
               << L" signal(s), " << skipped << L" unreadable file(s).\n"
               << L"Signals are heuristic indicators, not a definitive verdict.\n";
    if (skipped != 0) return 2;
    if (detected != 0) return 1;
    return 0;
}

void print_usage() {
    std::wcout <<
        L"SentinelGuard - native Windows static scanner and folder monitor\n"
        L"  SentinelGuard.exe scan <file-or-folder> [signature-db]\n"
        L"  SentinelGuard.exe monitor <folder> [signature-db]\n"
        L"  SentinelGuard.exe vt <file>        (uses SENTINELGUARD_VT_API_KEY)\n"
        L"  SentinelGuard.exe init-db <path>\n"
        L"  SentinelGuard.exe install-service <folder>\n"
        L"  SentinelGuard.exe uninstall-service\n"
        L"  SentinelGuard.exe --service <folder> <signature-db>\n"
        L"  SentinelGuard.exe --self-test\n\n"
        L"The monitor scans file changes after they are written; it cannot block execution.\n";
}

int self_test() {
    if (!sg_test_eicar_detector()) {
        std::wcerr << L"Self-test failed: built-in test signature was not detected.\n";
        return 1;
    }
    std::wcout << L"Self-test passed: built-in test signature detected in memory; no test file was written.\n";
    return 0;
}
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && std::wstring(argv[1]) == L"--self-test") return self_test();
    if (argc == 4 && std::wstring(argv[1]) == L"--service") {
        return sg_run_service(argv[2], argv[3]);
    }
    if (argc < 2) {
        print_usage();
        return 0;
    }

    const std::wstring command(argv[1]);
    const std::wstring database = default_database_path();
    if (command == L"scan" && (argc == 3 || argc == 4)) {
        return scan_target(argv[2], argc == 4 ? argv[3] : database);
    }
    if (command == L"monitor" && (argc == 3 || argc == 4)) {
        std::error_code db_error;
        const auto selected_database = argc == 4 ? std::wstring(argv[3]) : database;
        if (!std::filesystem::exists(selected_database, db_error) || db_error) {
            std::wcerr << L"Warning: local hash database is unavailable: " << selected_database
                       << L". Built-in static checks will still run.\n";
        }
        HANDLE stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event) {
            std::wcerr << L"Could not create stop event.\n";
            return 1;
        }
        g_console_stop_event = stop_event;
        SetConsoleCtrlHandler(console_handler, TRUE);
        const int result = sg_run_monitor(argv[2], selected_database, stop_event);
        SetConsoleCtrlHandler(console_handler, FALSE);
        g_console_stop_event = nullptr;
        CloseHandle(stop_event);
        return result;
    }
    if (command == L"vt" && argc == 3) {
        wchar_t *key = nullptr;
        size_t key_length = 0;
        const errno_t environment_status =
            _wdupenv_s(&key, &key_length, L"SENTINELGUARD_VT_API_KEY");
        const int result = sg_lookup_virustotal(argv[2],
                                                environment_status == 0 && key ? key : L"");
        free(key);
        return result;
    }
    if (command == L"init-db" && argc == 3) {
        const int result = sg_write_default_database(argv[2]);
        if (result == 0) std::wcout << L"Created empty SHA-256 signature database: " << argv[2] << L'\n';
        else std::wcerr << L"Could not create database (error " << result << L").\n";
        return result == 0 ? 0 : 1;
    }
    if (command == L"install-service" && argc == 3) {
        return sg_install_service(argv[2], database);
    }
    if (command == L"uninstall-service" && argc == 2) {
        return sg_uninstall_service();
    }

    print_usage();
    return 2;
}
