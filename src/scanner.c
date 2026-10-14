#include <windows.h>
#include <bcrypt.h>
#include <errno.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdlib.h>
#include "sg_scanner.h"

static const unsigned char eicar_marker_part_a[] =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-";
static const unsigned char eicar_marker_part_b[] =
    "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
static const wchar_t hex_digits[] = L"0123456789abcdef";

static size_t build_eicar_marker(unsigned char *marker) {
    const size_t part_a_length = sizeof(eicar_marker_part_a) - 1;
    const size_t part_b_length = sizeof(eicar_marker_part_b) - 1;
    memcpy(marker, eicar_marker_part_a, part_a_length);
    memcpy(marker + part_a_length, eicar_marker_part_b, part_b_length);
    return part_a_length + part_b_length;
}

static void set_detection(SGScanResult *result, unsigned int score, const wchar_t *rule) {
    if (score > result->score) {
        result->score = score;
        wcsncpy_s(result->rule, sizeof(result->rule) / sizeof(result->rule[0]), rule, _TRUNCATE);
    }
    result->detected = 1;
}

static int hash_matches_database(const wchar_t *database_path, const wchar_t *hash,
                                 SGScanResult *result) {
    if (database_path == NULL || database_path[0] == L'\0') {
        return 0;
    }

    FILE *database = NULL;
    if (_wfopen_s(&database, database_path, L"rt, ccs=UTF-8") != 0 || database == NULL) {
        return 0;
    }

    wchar_t line[512];
    int matched = 0;
    while (fgetws(line, (int)_countof(line), database) != NULL) {
        wchar_t *separator = wcschr(line, L'|');
        if (separator == NULL) continue;
        *separator = L'\0';
        wchar_t *entry_hash = line;
        while (*entry_hash == L' ' || *entry_hash == L'\t') ++entry_hash;
        wchar_t *hash_end = entry_hash + wcslen(entry_hash);
        while (hash_end > entry_hash &&
               (hash_end[-1] == L' ' || hash_end[-1] == L'\t' ||
                hash_end[-1] == L'\r' || hash_end[-1] == L'\n')) {
            *--hash_end = L'\0';
        }
        wchar_t *name = separator + 1;
        while (*name == L' ' || *name == L'\t') ++name;
        wchar_t *name_end = name + wcslen(name);
        while (name_end > name &&
               (name_end[-1] == L' ' || name_end[-1] == L'\t' ||
                name_end[-1] == L'\r' || name_end[-1] == L'\n')) {
            *--name_end = L'\0';
        }
        if (entry_hash[0] != L'#' && entry_hash[0] != L'\0' && name[0] != L'\0' &&
            _wcsicmp(entry_hash, hash) == 0) {
            set_detection(result, 100, name);
            matched = 1;
            break;
        }
    }

    fclose(database);
    return matched;
}

static int contains_ascii_icase(const unsigned char *bytes, size_t length, const char *needle) {
    const size_t needle_length = strlen(needle);
    if (needle_length == 0 || needle_length > length) return 0;
    for (size_t i = 0; i <= length - needle_length; ++i) {
        size_t j = 0;
        while (j < needle_length) {
            unsigned char ch = bytes[i + j];
            if (ch >= 'A' && ch <= 'Z') ch = (unsigned char)(ch + ('a' - 'A'));
            if (ch != (unsigned char)needle[j]) break;
            ++j;
        }
        if (j == needle_length) return 1;
    }
    return 0;
}

static void check_chunk(const unsigned char *bytes, size_t length, int *eicar_found,
                        int *has_shell, int *has_persistence, int *has_download,
                        int *has_loader, int *has_credential, int *has_macro,
                        int *has_obfuscation, int *has_service) {
    unsigned char marker[sizeof(eicar_marker_part_a) + sizeof(eicar_marker_part_b) - 2];
    const size_t marker_length = build_eicar_marker(marker);
    if (!*eicar_found && length >= marker_length) {
        for (size_t i = 0; i <= length - marker_length; ++i) {
            if (memcmp(bytes + i, marker, marker_length) == 0) {
                *eicar_found = 1;
                break;
            }
        }
    }

    if (contains_ascii_icase(bytes, length, "powershell") ||
        contains_ascii_icase(bytes, length, "cmd.exe /c") ||
        contains_ascii_icase(bytes, length, "wscript.shell")) {
        *has_shell = 1;
    }
    if (contains_ascii_icase(bytes, length, "currentversion\\run") ||
        contains_ascii_icase(bytes, length, "schtasks /create")) {
        *has_persistence = 1;
    }
    if (contains_ascii_icase(bytes, length, "downloadstring") ||
        contains_ascii_icase(bytes, length, "invoke-webrequest")) {
        *has_download = 1;
    }
    if (contains_ascii_icase(bytes, length, "rundll32") ||
        contains_ascii_icase(bytes, length, "regsvr32") ||
        contains_ascii_icase(bytes, length, "mshta")) {
        *has_loader = 1;
    }
    if (contains_ascii_icase(bytes, length, "mimikatz") ||
        contains_ascii_icase(bytes, length, "sekurlsa") ||
        contains_ascii_icase(bytes, length, "lsass")) {
        *has_credential = 1;
    }
    if (contains_ascii_icase(bytes, length, "autoopen") &&
        (contains_ascii_icase(bytes, length, "wscript.shell") ||
         contains_ascii_icase(bytes, length, "createobject"))) {
        *has_macro = 1;
    }
    if (contains_ascii_icase(bytes, length, "frombase64string") ||
        contains_ascii_icase(bytes, length, "encodedcommand")) {
        *has_obfuscation = 1;
    }
    if ((contains_ascii_icase(bytes, length, "sc.exe create") ||
         contains_ascii_icase(bytes, length, "new-service")) &&
        (contains_ascii_icase(bytes, length, "binpath") ||
         contains_ascii_icase(bytes, length, "binarypathname"))) {
        *has_service = 1;
    }
}

static int is_current_executable(const wchar_t *path) {
    wchar_t executable[MAX_PATH];
    wchar_t candidate[MAX_PATH];
    const DWORD executable_length = GetModuleFileNameW(NULL, executable, (DWORD)_countof(executable));
    const DWORD candidate_length = GetFullPathNameW(path, (DWORD)_countof(candidate), candidate, NULL);
    if (executable_length == 0 || executable_length >= _countof(executable) ||
        candidate_length == 0 || candidate_length >= _countof(candidate)) {
        return 0;
    }
    return CompareStringOrdinal(executable, -1, candidate, -1, TRUE) == CSTR_EQUAL;
}

int sg_test_eicar_detector(void) {
    unsigned char marker[sizeof(eicar_marker_part_a) + sizeof(eicar_marker_part_b) - 2];
    const size_t marker_length = build_eicar_marker(marker);
    int found = 0, shell = 0, persistence = 0, download = 0;
    int loader = 0, credential = 0, macro = 0, obfuscation = 0, service = 0;
    check_chunk(marker, marker_length, &found, &shell, &persistence, &download,
                &loader, &credential, &macro, &obfuscation, &service);
    return found;
}

int sg_scan_file(const wchar_t *path, const wchar_t *database_path, SGScanResult *result) {
    if (path == NULL || result == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    SecureZeroMemory(result, sizeof(*result));

    FILE *file = NULL;
    if (_wfopen_s(&file, path, L"rb") != 0 || file == NULL) {
        return errno != 0 ? errno : ERROR_FILE_NOT_FOUND;
    }

    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash_handle = NULL;
    DWORD object_length = 0;
    DWORD returned = 0;
    PUCHAR hash_object = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status >= 0) {
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_length,
                                   sizeof(object_length), &returned, 0);
    }
    if (status >= 0) {
        hash_object = (PUCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, object_length);
        if (hash_object == NULL) {
            status = (NTSTATUS)0xC0000017L;
        }
    }
    if (status >= 0) {
        status = BCryptCreateHash(algorithm, &hash_handle, hash_object, object_length, NULL, 0, 0);
    }
    if (status < 0) {
        if (hash_object != NULL) HeapFree(GetProcessHeap(), 0, hash_object);
        if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
        fclose(file);
        return (int)status;
    }

    unsigned char buffer[64 * 1024 + sizeof(eicar_marker_part_a) + sizeof(eicar_marker_part_b)];
    size_t carry = 0;
    int eicar_found = 0;
    int has_shell = 0;
    int has_persistence = 0;
    int has_download = 0;
    int has_loader = 0;
    int has_credential = 0;
    int has_macro = 0;
    int has_obfuscation = 0;
    int has_service = 0;
    const int scanning_self = is_current_executable(path);
    size_t bytes_read = 0;
    do {
        bytes_read = fread(buffer + carry, 1, 64 * 1024, file);
        const size_t available = carry + bytes_read;
        if (available > 0) {
            status = BCryptHashData(hash_handle, buffer + carry, (ULONG)bytes_read, 0);
            if (status < 0) break;
            check_chunk(buffer, available, &eicar_found, &has_shell, &has_persistence,
                        &has_download, &has_loader, &has_credential, &has_macro,
                        &has_obfuscation, &has_service);
        }
        const size_t marker_capacity = sizeof(eicar_marker_part_a) + sizeof(eicar_marker_part_b) - 2;
        carry = available < marker_capacity ? available : marker_capacity - 1;
        if (carry > 0) {
            memmove(buffer, buffer + available - carry, carry);
        }
    } while (bytes_read == 64 * 1024);

    if (ferror(file)) {
        status = (NTSTATUS)0xC0000001L;
    }

    unsigned char digest[32];
    if (status >= 0) {
        status = BCryptFinishHash(hash_handle, digest, sizeof(digest), 0);
    }
    fclose(file);

    if (status >= 0) {
        for (size_t i = 0; i < sizeof(digest); ++i) {
            result->sha256[i * 2] = hex_digits[digest[i] >> 4];
            result->sha256[i * 2 + 1] = hex_digits[digest[i] & 0x0f];
        }
        result->sha256[64] = L'\0';
        if (eicar_found) set_detection(result, 100, L"EICAR test signature");
        if (!scanning_self && has_shell) set_detection(result, 25, L"Suspicious shell/script token");
        if (!scanning_self && has_persistence) set_detection(result, 35, L"Persistence-related token");
        if (!scanning_self && has_download) set_detection(result, 30, L"Remote retrieval token");
        if (!scanning_self && has_loader) set_detection(result, 28, L"Suspicious loader token");
        if (!scanning_self && has_credential) set_detection(result, 35, L"Credential-access token");
        if (!scanning_self && has_macro) set_detection(result, 25, L"Macro execution token");
        if (!scanning_self && has_obfuscation) set_detection(result, 30, L"Obfuscated command token");
        if (!scanning_self && has_service) set_detection(result, 30, L"Service installation token");
        (void)hash_matches_database(database_path, result->sha256, result);
    }

    BCryptDestroyHash(hash_handle);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    HeapFree(GetProcessHeap(), 0, hash_object);
    return status < 0 ? (int)status : 0;
}

int sg_write_default_database(const wchar_t *path) {
    if (path == NULL) return ERROR_INVALID_PARAMETER;
    FILE *file = NULL;
    if (_wfopen_s(&file, path, L"wt, ccs=UTF-8") != 0 || file == NULL) {
        return errno != 0 ? errno : ERROR_ACCESS_DENIED;
    }
    fputws(L"# SHA-256|label; add only hashes from a trusted source.\n", file);
    fclose(file);
    return 0;
}
