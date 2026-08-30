#ifndef PRODUCT_H
#define PRODUCT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char *cve_id;
    uint32_t year;
    uint32_t number;
    char *product;
} Product;

typedef struct {
    Product *items;
    size_t count;
    size_t capacity;
} ProductArray;

int product_array_load_csv(ProductArray *array, const char *path);
void product_array_free(ProductArray *array);
int product_compare_key(const Product *left, const Product *right);
int product_array_is_sorted_by_key(const ProductArray *array);

/* Busca binaria por limite inferior: retorna o indice do primeiro elemento
 * cuja chave (year, number) nao seja menor que a chave buscada (ou seja,
 * o ponto onde essa chave poderia ser inserida mantendo a ordenacao).
 * Se todos os elementos forem menores, retorna array->count.
 * Requer que array esteja ordenado por chave crescente. */
size_t product_array_lower_bound(
    const ProductArray *array,
    uint32_t year,
    uint32_t number
);

/* Localiza os produtos associados ao CVE de chave (year, number). */
void product_array_find_for_cve(
    const ProductArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_start,
    size_t *out_count
);

#endif
