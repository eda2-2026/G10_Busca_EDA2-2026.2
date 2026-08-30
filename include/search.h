#ifndef SEARCH_H
#define SEARCH_H

#include <stddef.h>
#include <stdint.h>

#include "cve.h"

/* Busca binaria exata por chave (year, number) em um CVEArray.
 * Se encontrar, escreve o indice em *out_index e retorna 1.
 * Se nao encontrar (ou array/out_index forem NULL), retorna 0. */
int cve_array_binary_search(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index
);

#endif
