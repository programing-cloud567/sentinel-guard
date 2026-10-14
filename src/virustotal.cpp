#include "sg_runtime.hpp"
#include "sg_scanner.h"

#include <winhttp.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
std::wstring widen_ascii(const std::string &text) {
    return std::wstring(text.begin(), text.end());
}

bool read_count(const std::string &body, const std::string &key, unsigned long &value) {
    const std::string marker = "\"" + key + "\"";
    const auto key_position = body.find(marker);
    if (key_position == std::string::npos) return false;
    const auto colon = body.find(':', key_position + marker.size());
    if (colon == std::string::npos) return false;
    const char *start = body.c_str() + colon + 1;
    while (*start == ' ' || *start == '\t') ++start;
    char *end = nullptr;
    const auto parsed = std::strtoul(start, &end, 10);
    if (end == start) return false;
    value = parsed;
    return true;
}

struct WinHttpHandles {
    HINTERNET request = nullptr;
    HINTERNET connection = nullptr;
    HINTERNET session = nullptr;
    ~WinHttpHandles() {
        if (request) WinHttpCloseHandle(request);
        if (connection) WinHttpCloseHandle(connection);
        if (session) WinHttpCloseHandle(session);
    }
};
}

int sg_lookup_virustotal(const std::wstring &file_path, const std::wstring &api_key) {
    SGScanResult scan{};
    const int scan_status = sg_scan_file(file_path.c_str(), nullptr, &scan);
    if (scan_status != 0) {
        std::wcerr << L"Could not calculate file SHA-256 (status " << scan_status << L").\n";
        return 1;
    }
    if (api_key.empty()) {
        std::wcerr << L"Set SENTINELGUARD_VT_API_KEY to your VirusTotal API key first.\n";
        return 2;
    }
    if (api_key.size() > 256 ||
        api_key.find_first_of(L"\r\n") != std::wstring::npos) {
        std::wcerr << L"The VirusTotal API key has an invalid format.\n";
        return 2;
    }

    const std::wstring user_agent = L"SentinelGuard/0.1";
    const std::wstring endpoint = L"/api/v3/files/" + std::wstring(scan.sha256);
    const std::wstring headers = L"x-apikey: " + api_key + L"\r\n";
    WinHttpHandles handles;
    handles.session = WinHttpOpen(user_agent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!handles.session) {
        std::wcerr << L"Could not initialize HTTPS client (error " << GetLastError() << L").\n";
        return 1;
    }
    WinHttpSetTimeouts(handles.session, 5000, 5000, 10000, 10000);
    handles.connection = WinHttpConnect(handles.session, L"www.virustotal.com",
                                        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!handles.connection) {
        std::wcerr << L"Could not connect to VirusTotal (error " << GetLastError() << L").\n";
        return 1;
    }
    handles.request = WinHttpOpenRequest(handles.connection, L"GET", endpoint.c_str(), nullptr,
                                         WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_SECURE);
    if (!handles.request) {
        std::wcerr << L"Could not create HTTPS request (error " << GetLastError() << L").\n";
        return 1;
    }
    if (!WinHttpSendRequest(handles.request, headers.c_str(),
                            static_cast<DWORD>(headers.size()), WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(handles.request, nullptr)) {
        std::wcerr << L"VirusTotal request failed (error " << GetLastError() << L").\n";
        return 1;
    }

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(handles.request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                             WINHTTP_NO_HEADER_INDEX)) {
        std::wcerr << L"Could not read VirusTotal response status.\n";
        return 1;
    }
    if (status == 404) {
        std::wcout << L"VirusTotal has no report for SHA-256 " << scan.sha256 << L".\n";
        return 0;
    }
    if (status == 429) {
        std::wcerr << L"VirusTotal rate limit reached (HTTP 429).\n";
        return 1;
    }
    if (status < 200 || status >= 300) {
        std::wcerr << L"VirusTotal returned HTTP " << status << L". Check API key and quota.\n";
        return 1;
    }

    std::string body;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(handles.request, &available)) {
            std::wcerr << L"Could not read VirusTotal response (error " << GetLastError() << L").\n";
            return 1;
        }
        if (available == 0) break;
        if (body.size() + available > 4 * 1024 * 1024) {
            std::wcerr << L"VirusTotal response exceeded the 4 MiB safety limit.\n";
            return 1;
        }
        std::vector<char> chunk(available);
        DWORD read = 0;
        if (!WinHttpReadData(handles.request, chunk.data(), available, &read)) {
            std::wcerr << L"Could not read VirusTotal response (error " << GetLastError() << L").\n";
            return 1;
        }
        body.append(chunk.data(), read);
    }

    unsigned long malicious = 0, suspicious = 0, harmless = 0, undetected = 0;
    if (!read_count(body, "malicious", malicious) ||
        !read_count(body, "suspicious", suspicious) ||
        !read_count(body, "harmless", harmless) ||
        !read_count(body, "undetected", undetected)) {
        std::wcerr << L"VirusTotal response did not contain the expected analysis statistics.\n";
        return 1;
    }
    std::wcout << L"SHA-256: " << scan.sha256 << L"\n"
               << L"VirusTotal engines: malicious=" << malicious
               << L", suspicious=" << suspicious << L", harmless=" << harmless
               << L", undetected=" << undetected << L"\n"
               << L"Only the hash was queried; the file contents were not uploaded.\n";
    return 0;
}
