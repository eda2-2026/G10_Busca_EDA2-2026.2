#ifndef CVE_H
#define CVE_H

#include <stddef.h>

typedef enum {
    CVE_STATE_PUBLISHED,
    CVE_STATE_REJECTED
} CVEState;

typedef struct {
    char *cve_id;
    CVEState state;
    char *description_en;
    char *title;
    char *rejection_reason_en;
} CVE;

typedef struct {
    CVE *items;
    size_t count;
    size_t capacity;
} CVEArray;

int cve_array_load_csv(CVEArray *array, const char *path);
void cve_array_free(CVEArray *array);

#endif
