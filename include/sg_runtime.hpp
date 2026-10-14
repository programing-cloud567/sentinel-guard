#ifndef SENTINEL_GUARD_RUNTIME_HPP
#define SENTINEL_GUARD_RUNTIME_HPP

#include <windows.h>
#include <string>

int sg_run_monitor(const std::wstring &directory, const std::wstring &database_path, HANDLE stop_event);
int sg_run_service(const std::wstring &directory, const std::wstring &database_path);
int sg_install_service(const std::wstring &directory, const std::wstring &database_path);
int sg_uninstall_service();
int sg_lookup_virustotal(const std::wstring &file_path, const std::wstring &api_key);

#endif
