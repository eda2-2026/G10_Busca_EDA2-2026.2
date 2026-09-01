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

/* O(n): percorre o array do inicio ao fim comparando cada elemento. Nao
 * exige que o array esteja ordenado. Serve como referencia "burra e
 * confiavel" para validar cve_array_binary_search, e como base de
 * comparacao no benchmark (bin/cve_bench). Mesma convencao de retorno de
 * cve_array_binary_search. */
int cve_array_linear_search(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index
);

/* Mesmas duas buscas acima, mas tambem contando quantas comparacoes de
 * chave (cve_compare_key) foram feitas - usado pelo benchmark para medir
 * o custo de cada algoritmo de um jeito que nao depende da velocidade da
 * maquina. out_comparisons pode ser NULL (nesse caso nao conta nada); e'
 * exatamente o que cve_array_binary_search/cve_array_linear_search fazem
 * por baixo. */
int cve_array_binary_search_counted(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index,
    size_t *out_comparisons
);

int cve_array_linear_search_counted(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index,
    size_t *out_comparisons
);

#endif
