#include "product_index.h"

#include <stdint.h>
#include <stdlib.h>

static unsigned char fold_ascii(unsigned char value)
{
    if (value >= (unsigned char)'A' && value <= (unsigned char)'Z') {
        return (unsigned char)(value + ((unsigned char)'a' - (unsigned char)'A'));
    }
    return value;
}

int product_name_compare_ascii(const char *left, const char *right)
{
    if (left == NULL) {
        return right == NULL ? 0 : -1;
    }
    if (right == NULL) {
        return 1;
    }

    while (*left != '\0' && *right != '\0') {
        unsigned char left_value = fold_ascii((unsigned char)*left);
        unsigned char right_value = fold_ascii((unsigned char)*right);

        if (left_value < right_value) {
            return -1;
        }
        if (left_value > right_value) {
            return 1;
        }
        ++left;
        ++right;
    }

    if (*left == '\0' && *right == '\0') {
        return 0;
    }
    return *left == '\0' ? -1 : 1;
}

static int compare_entries(const void *left_value, const void *right_value)
{
    const ProductNameIndexEntry *left = left_value;
    const ProductNameIndexEntry *right = right_value;
    int comparison = product_name_compare_ascii(left->product_name, right->product_name);

    if (comparison != 0) {
        return comparison;
    }

    if (left->product_index < right->product_index) {
        return -1;
    }
    if (left->product_index > right->product_index) {
        return 1;
    }
    return 0;
}

int product_name_index_build(
    ProductNameIndex *index,
    const ProductArray *products
)
{
    ProductNameIndexEntry *entries;
    size_t read_index;

    if (index == NULL || products == NULL
        || index->items != NULL || index->count != 0U || index->source != NULL
        || (products->count > 0U && products->items == NULL)) {
        return 0;
    }

    if (products->count == 0U) {
        index->source = products;
        return 1;
    }

    if (products->count > SIZE_MAX / sizeof(*entries)) {
        return 0;
    }

    entries = malloc(products->count * sizeof(*entries));
    if (entries == NULL) {
        return 0;
    }

    for (read_index = 0U; read_index < products->count; ++read_index) {
        const Product *product = &products->items[read_index];

        if (product->cve_id == NULL || product->cve_id[0] == '\0'
            || product->product == NULL || product->product[0] == '\0') {
            free(entries);
            return 0;
        }

        entries[read_index].product_name = product->product;
        entries[read_index].product_index = read_index;
    }

    qsort(entries, products->count, sizeof(*entries), compare_entries);

    index->items = entries;
    index->count = products->count;
    index->source = products;
    return 1;
}

void product_name_index_free(ProductNameIndex *index)
{
    if (index == NULL) {
        return;
    }

    free(index->items);
    *index = (ProductNameIndex){0};
}

size_t product_name_index_lower_bound(
    const ProductNameIndex *index,
    const char *product_name
)
{
    size_t low;
    size_t high;

    if (index == NULL || product_name == NULL || index->source == NULL
        || (index->count > 0U && index->items == NULL)) {
        return 0U;
    }

    low = 0U;
    high = index->count;

    while (low < high) {
        size_t middle = low + (high - low) / 2U;
        int comparison = product_name_compare_ascii(
            index->items[middle].product_name,
            product_name
        );

        if (comparison < 0) {
            low = middle + 1U;
        } else {
            high = middle;
        }
    }

    return low;
}

int product_name_index_find_exact(
    const ProductNameIndex *index,
    const char *product_name,
    size_t *out_start,
    size_t *out_count
)
{
    size_t start;
    size_t count = 0U;

    if (out_start == NULL || out_count == NULL) {
        return 0;
    }
    *out_start = 0U;
    *out_count = 0U;

    if (index == NULL || product_name == NULL || product_name[0] == '\0'
        || index->source == NULL
        || (index->count > 0U && index->items == NULL)) {
        return 0;
    }

    start = product_name_index_lower_bound(index, product_name);
    while (start + count < index->count
        && product_name_compare_ascii(
            index->items[start + count].product_name,
            product_name
        ) == 0) {
        ++count;
    }

    *out_start = start;
    *out_count = count;
    return 1;
}

const Product *product_name_index_get(
    const ProductNameIndex *index,
    size_t result_position
)
{
    size_t product_index;

    if (index == NULL || index->source == NULL || result_position >= index->count
        || (index->count > 0U && index->items == NULL)) {
        return NULL;
    }

    product_index = index->items[result_position].product_index;
    if (product_index >= index->source->count || index->source->items == NULL) {
        return NULL;
    }

    return &index->source->items[product_index];
}
