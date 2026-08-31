#ifndef FINDER_H
#define FINDER_H

#include <stddef.h>

#include "cve.h"
#include "product.h"
#include "product_index.h"

typedef struct {
    int found;                /* 1 se o CVE existe na base, 0 caso contrario */
    const CVE *cve;           /* aponta para dentro do CVEArray recebido; valido so' se found */
    const Product *products;  /* aponta para o primeiro produto dentro do ProductArray recebido */
    size_t product_count;
} FinderResult;

typedef struct {
    const ProductNameIndex *index;
    size_t start;
    size_t count;
} ProductSearchResult;

/* Interpreta `raw_input` como um CVE-ID (tolera espacos nas pontas e
 * qualquer combinacao de maiusculas/minusculas), busca no array de CVEs
 * (busca binaria) e, se encontrado, localiza tambem os produtos
 * associados (busca binaria + varredura).
 *
 * Retorna 1 se `raw_input` tinha formato valido de CVE-ID - nesse caso
 * out_result->found diz se ele existe na base. Retorna 0 se o formato
 * era invalido (out_result fica zerado). */
int finder_search(
    const CVEArray *cves,
    const ProductArray *products,
    const char *raw_input,
    FinderResult *out_result
);

/*
 * Busca exata por nome no ProductNameIndex existente. Retorna 1 para uma
 * consulta valida, inclusive quando nenhum produto e' encontrado (count == 0).
 * Retorna 0 para argumentos ou nome invalidos e zera out_result quando ele
 * estiver disponivel. Os resultados ocupam [start, start + count) no indice.
 */
int finder_search_product(
    const ProductNameIndex *index,
    const char *product_name,
    ProductSearchResult *out_result
);

#endif
