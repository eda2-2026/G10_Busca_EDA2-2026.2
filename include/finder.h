#ifndef FINDER_H
#define FINDER_H

#include <stddef.h>

#include "cve.h"
#include "product.h"

typedef struct {
    int found;                /* 1 se o CVE existe na base, 0 caso contrario */
    const CVE *cve;           /* aponta para dentro do CVEArray recebido; valido so' se found */
    const Product *products;  /* aponta para o primeiro produto dentro do ProductArray recebido */
    size_t product_count;
} FinderResult;

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

#endif
