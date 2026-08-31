#ifndef PRODUCT_INDEX_H
#define PRODUCT_INDEX_H

#include <stddef.h>

#include "product.h"

typedef struct {
    const char *product_name;
    size_t product_index;
} ProductNameIndexEntry;

typedef struct {
    ProductNameIndexEntry *items;
    size_t count;
    const ProductArray *source;
} ProductNameIndex;

/*
 * O indice possui exatamente uma entrada para cada relacao de `products`.
 * Apos uma construcao bem-sucedida, index->count == index->source->count.
 * Ele nao altera nem deduplica os dados: apenas fornece uma ordenacao
 * secundaria por nome do produto.
 *
 * O indice apenas empresta strings e referencia elementos de `products`.
 * O ProductArray deve permanecer vivo e imutavel durante todo o uso do
 * indice. Qualquer alteracao no ProductArray exige reconstruir o indice.
 * O indice deve ser liberado antes do ProductArray.
 */
int product_name_index_build(
    ProductNameIndex *index,
    const ProductArray *products
);

void product_name_index_free(ProductNameIndex *index);

/*
 * Compara nomes ignorando caixa somente para os caracteres ASCII A-Z/a-z.
 * Dois ponteiros NULL sao iguais; NULL e' menor que qualquer nome nao nulo.
 */
int product_name_compare_ascii(const char *left, const char *right);

/*
 * Busca binaria por limite inferior. Retorna a primeira posicao cuja chave
 * nao e' menor que `product_name`. Argumentos invalidos retornam 0.
 */
size_t product_name_index_lower_bound(
    const ProductNameIndex *index,
    const char *product_name
);

/*
 * Em uma chamada valida, retorna 1 e preenche o intervalo de resultados
 * [out_start, out_start + out_count). Produto inexistente e' uma busca valida
 * com out_count igual a zero e out_start igual ao ponto de insercao.
 * Retorna 0 para argumentos invalidos, incluindo nome vazio.
 */
int product_name_index_find_exact(
    const ProductNameIndex *index,
    const char *product_name,
    size_t *out_start,
    size_t *out_count
);

/* Retorna o Product original de uma posicao do resultado, ou NULL. */
const Product *product_name_index_get(
    const ProductNameIndex *index,
    size_t result_position
);

#endif
