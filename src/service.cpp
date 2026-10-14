#include "sg_runtime.hpp"
#include "sg_scanner.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>

namespace {
constexpr wchar_t kServiceName[] = L"SentinelGuardMonitor";
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
std::wstring g_watch_directory;
std::wstring g_database_path;

void report_status(DWORD state, DWORD error = NO_ERROR, DWORD wait_hint = 0) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = error;
    g_status.dwWaitHint = wait_hint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    if (g_status_handle) SetServiceStatus(g_status_handle, &g_status);
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        report_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        if (g_stop_event) SetEvent(g_stop_event);
    }
    return NO_ERROR;
}

void WINAPI service_main(DWORD, LPWSTR *) {
    g_status_handle = RegisterServiceCtrlHandlerExW(kServiceName, control_handler, nullptr);
    if (!g_status_handle) return;
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event) {
        report_status(SERVICE_STOPPED, GetLastError());
        return;
    }
    report_status(SERVICE_RUNNING);
    const int result = sg_run_monitor(g_watch_directory, g_database_path, g_stop_event);
    report_status(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
    CloseHandle(g_stop_event);
    g_stop_event = nullptr;
}
}

int sg_run_service(const std::wstring &directory, const std::wstring &database_path) {
    g_watch_directory = directory;
    g_database_path = database_path;
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), service_main},
        {nullptr, nullptr}
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        std::wcerr << L"Could not start service dispatcher (error " << GetLastError() << L").\n";
        return 1;
    }
    return 0;
}

int sg_install_service(const std::wstring &directory, const std::wstring &database_path) {
    wchar_t executable[MAX_PATH]{};
    const DWORD length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        std::wcerr << L"Could not locate the SentinelGuard executable.\n";
        return 1;
    }

    std::wstring service_database = database_path;
    wchar_t *program_data = nullptr;
    size_t program_data_length = 0;
    if (_wdupenv_s(&program_data, &program_data_length, L"ProgramData") == 0 &&
        program_data != nullptr && program_data_length > 1) {
        const auto shared_directory = std::filesystem::path(program_data) / L"SentinelGuard";
        std::error_code error;
        std::filesystem::create_directories(shared_directory, error);
        if (!error) {
            const auto shared_database = shared_directory / L"signatures.txt";
            if (!std::filesystem::exists(shared_database, error) && !error) {
                if (std::filesystem::exists(database_path, error) && !error) {
                    std::filesystem::copy_file(database_path, shared_database,
                        std::filesystem::copy_options::none, error);
                    if (error) {
                        free(program_data);
                        std::wcerr << L"Could not copy the local signature database (error "
                                   << error.value() << L").\n";
                        return 1;
                    }
                } else if (!error) {
                    const int create_result = sg_write_default_database(shared_database.c_str());
                    if (create_result != 0) {
                        free(program_data);
                        std::wcerr << L"Could not create shared signature database (error "
                                   << create_result << L").\n";
                        return 1;
                    }
                }
            }
            if (!error) service_database = shared_database.wstring();
        }
    }
    free(program_data);

    const std::wstring command_line = L"\"" + std::wstring(executable) + L"\" --service \"" +
                                     directory + L"\" \"" + service_database + L"\"";
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!manager) {
        std::wcerr << L"Open an elevated terminal to install the service (error "
                   << GetLastError() << L").\n";
        return 1;
    }
    SC_HANDLE service = CreateServiceW(manager, kServiceName, L"SentinelGuard folder monitor",
        SERVICE_START | DELETE | SERVICE_QUERY_STATUS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command_line.c_str(), nullptr, nullptr,
        nullptr, nullptr, nullptr);
    if (!service) {
        const DWORD error = GetLastError();
        CloseServiceHandle(manager);
        std::wcerr << L"Could not create service (error " << error
                   << L"). The service may already exist.\n";
        return 1;
    }
    const BOOL started = StartServiceW(service, 0, nullptr);
    const DWORD error = started ? NO_ERROR : GetLastError();
    if (!started) DeleteService(service);
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!started) {
        std::wcerr << L"Service was installed but could not start (error " << error << L").\n";
        return 1;
    }
    std::wcout << L"SentinelGuard monitor service installed and started.\n"
               << L"It monitors only: " << directory << L"\n"
               << L"Signature database: " << service_database << L"\n";
    return 0;
}

int sg_uninstall_service() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        std::wcerr << L"Could not open Service Control Manager (error " << GetLastError() << L").\n";
        return 1;
    }
    SC_HANDLE service = OpenServiceW(manager, kServiceName,
                                     SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!service) {
        const DWORD error = GetLastError();
        CloseServiceHandle(manager);
        std::wcerr << L"Could not open SentinelGuard service (error " << error << L").\n";
        return 1;
    }
    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);
    const BOOL deleted = DeleteService(service);
    const DWORD error = deleted ? NO_ERROR : GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!deleted) {
        std::wcerr << L"Could not remove service (error " << error << L").\n";
        return 1;
    }
    std::wcout << L"SentinelGuard monitor service removed.\n";
    return 0;
}
