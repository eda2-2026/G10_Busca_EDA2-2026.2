#ifndef CVE_H
#define CVE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    CVE_STATE_PUBLISHED,
    CVE_STATE_REJECTED
} CVEState;

typedef struct {
    char *cve_id;
    uint32_t year;
    uint32_t number;
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
int cve_compare_key(const CVE *left, const CVE *right);
int cve_array_is_sorted_by_key(const CVEArray *array);

/* Extrai year/number de um cve_id no formato "CVE-AAAA-N...N" (N >= 4
 * digitos, sem zero a esquerda alem dos 4 minimos, ano e numero > 0).
 * Retorna 1 e preenche *year e *number em sucesso, 0 se o formato for
 * invalido. Publica porque product.c (Fase 2) reutiliza a mesma chave
 * para relacionar produtos a CVEs. */
int cve_parse_key(const char *cve_id, uint32_t *year, uint32_t *number);

#endif
