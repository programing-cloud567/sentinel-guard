#ifndef SENTINEL_GUARD_SCANNER_H
#define SENTINEL_GUARD_SCANNER_H

#include <stddef.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SGScanResult {
    wchar_t sha256[65];
    unsigned int score;
    int detected;
    wchar_t rule[128];
} SGScanResult;

int sg_scan_file(const wchar_t *path, const wchar_t *database_path, SGScanResult *result);
int sg_write_default_database(const wchar_t *path);
int sg_test_eicar_detector(void);

#ifdef __cplusplus
}
#endif

#endif
