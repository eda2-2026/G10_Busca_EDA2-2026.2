#include "finder.h"
#include "search.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#define MAX_NORMALIZED_LENGTH 63U

/* Remove espacos nas pontas de raw_input e converte para maiusculas,
 * gravando o resultado em `out` (capacidade out_capacity, incluindo o
 * '\0'). Retorna 0 se sobrar vazio ou nao couber no buffer. */
static int normalize_cve_id(const char *raw_input, char *out, size_t out_capacity)
{
    size_t start = 0U;
    size_t end;
    size_t length;
    size_t index;

    if (raw_input == NULL) {
        return 0;
    }

    length = strlen(raw_input);

    while (start < length && isspace((unsigned char)raw_input[start])) {
        ++start;
    }
    end = length;
    while (end > start && isspace((unsigned char)raw_input[end - 1U])) {
        --end;
    }

    length = end - start;
    if (length == 0U || length >= out_capacity) {
        return 0;
    }

    for (index = 0U; index < length; ++index) {
        out[index] = (char)toupper((unsigned char)raw_input[start + index]);
    }
    out[length] = '\0';
    return 1;
}

int finder_search(
    const CVEArray *cves,
    const ProductArray *products,
    const char *raw_input,
    FinderResult *out_result
)
{
    char normalized[MAX_NORMALIZED_LENGTH + 1U];
    uint32_t year;
    uint32_t number;
    size_t cve_index;

    if (cves == NULL || products == NULL || raw_input == NULL || out_result == NULL) {
        return 0;
    }

    *out_result = (FinderResult){0};

    if (!normalize_cve_id(raw_input, normalized, sizeof(normalized))
        || !cve_parse_key(normalized, &year, &number)) {
        return 0;
    }

    if (!cve_array_binary_search(cves, year, number, &cve_index)) {
        return 1; /* formato valido, mas esse CVE nao existe na base */
    }

    out_result->found = 1;
    out_result->cve = &cves->items[cve_index];

    {
        size_t product_start;
        size_t product_count;

        product_array_find_for_cve(products, year, number, &product_start, &product_count);
        out_result->products = product_count > 0U ? &products->items[product_start] : NULL;
        out_result->product_count = product_count;
    }

    return 1;
}

int finder_search_product(
    const ProductNameIndex *index,
    const char *product_name,
    ProductSearchResult *out_result
)
{
    size_t start;
    size_t count;

    if (out_result == NULL) {
        return 0;
    }
    *out_result = (ProductSearchResult){0};

    if (index == NULL || product_name == NULL
        || !product_name_index_find_exact(index, product_name, &start, &count)) {
        return 0;
    }

    out_result->index = index;
    out_result->start = start;
    out_result->count = count;
    return 1;
}
