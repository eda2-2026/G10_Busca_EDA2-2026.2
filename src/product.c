#include "product.h"
#include "cve.h"
#include "csv.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PRODUCT_FIELD_COUNT 2U
#define INITIAL_ARRAY_CAPACITY 1024U

static void product_release(Product *product)
{
    if (product == NULL) {
        return;
    }

    free(product->cve_id);
    free(product->product);
    *product = (Product){0};
}

void product_array_free(ProductArray *array)
{
    size_t index;

    if (array == NULL) {
        return;
    }

    for (index = 0; index < array->count; ++index) {
        product_release(&array->items[index]);
    }

    free(array->items);
    *array = (ProductArray){0};
}

int product_compare_key(const Product *left, const Product *right)
{
    if (left->year < right->year) {
        return -1;
    }
    if (left->year > right->year) {
        return 1;
    }
    if (left->number < right->number) {
        return -1;
    }
    if (left->number > right->number) {
        return 1;
    }
    return 0;
}

int product_array_is_sorted_by_key(const ProductArray *array)
{
    size_t index;

    if (array == NULL || (array->count > 0U && array->items == NULL)) {
        return 0;
    }

    for (index = 1U; index < array->count; ++index) {
        if (product_compare_key(&array->items[index - 1U], &array->items[index]) > 0) {
            return 0;
        }
    }

    return 1;
}

size_t product_array_lower_bound(
    const ProductArray *array,
    uint32_t year,
    uint32_t number
)
{
    size_t low = 0U;
    size_t high = array->count;

    while (low < high) {
        size_t mid = low + (high - low) / 2U;
        const Product *candidate = &array->items[mid];
        int is_less = candidate->year < year
            || (candidate->year == year && candidate->number < number);

        if (is_less) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }

    return low;
}

void product_array_find_for_cve(
    const ProductArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_start,
    size_t *out_count
)
{
    size_t start = product_array_lower_bound(array, year, number);
    size_t count = 0U;

    while (start + count < array->count
        && array->items[start + count].year == year
        && array->items[start + count].number == number) {
        ++count;
    }

    *out_start = start;
    *out_count = count;
}

static int build_product(char **fields, Product *product)
{
    if (!cve_parse_key(fields[0], &product->year, &product->number)) {
        return 0;
    }

    product->cve_id = fields[0];
    fields[0] = NULL;
    product->product = csv_decode_text(fields[1]);

    if (product->product == NULL || product->product[0] == '\0') {
        product_release(product);
        return 0;
    }

    return 1;
}

static int append_product(ProductArray *array, Product *product)
{
    Product *resized;
    size_t new_capacity;

    if (array->count == array->capacity) {
        new_capacity = array->capacity == 0U
            ? INITIAL_ARRAY_CAPACITY
            : array->capacity * 2U;

        if (new_capacity < array->capacity
            || new_capacity > SIZE_MAX / sizeof(*array->items)) {
            return 0;
        }

        resized = realloc(array->items, new_capacity * sizeof(*array->items));
        if (resized == NULL) {
            return 0;
        }
        array->items = resized;
        array->capacity = new_capacity;
    }

    array->items[array->count++] = *product;
    *product = (Product){0};
    return 1;
}

int product_array_load_csv(ProductArray *array, const char *path)
{
    static const char *const expected_header[PRODUCT_FIELD_COUNT] = {
        "cve_id",
        "product"
    };
    FILE *file;
    char *line = NULL;
    size_t line_capacity = 0U;
    size_t line_length = 0U;
    size_t physical_line = 0U;
    char *fields[PRODUCT_FIELD_COUNT] = {0};
    int read_status;
    int success = 0;

    if (array == NULL || path == NULL
        || array->items != NULL || array->count != 0U || array->capacity != 0U) {
        fprintf(stderr, "Erro: argumentos invalidos para carregar o CSV.\n");
        return 0;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "Erro ao abrir %s: %s\n", path, strerror(errno));
        return 0;
    }

    read_status = csv_read_line(file, &line, &line_capacity, &line_length);
    if (read_status != 1
        || !csv_parse_line(line, fields, PRODUCT_FIELD_COUNT)) {
        fprintf(stderr, "Erro: cabecalho CSV ausente ou invalido.\n");
        goto cleanup;
    }
    physical_line = 1U;

    if (!csv_header_matches(fields, expected_header, PRODUCT_FIELD_COUNT)) {
        fprintf(stderr, "Erro: cabecalho inesperado em %s.\n", path);
        goto cleanup;
    }
    csv_free_fields(fields, PRODUCT_FIELD_COUNT);

    while ((read_status = csv_read_line(
                file, &line, &line_capacity, &line_length
            )) == 1) {
        Product product = {0};
        ++physical_line;

        if (!csv_parse_line(line, fields, PRODUCT_FIELD_COUNT)) {
            fprintf(stderr, "Erro: CSV malformado na linha %zu.\n", physical_line);
            goto cleanup;
        }
        if (!build_product(fields, &product)) {
            fprintf(stderr, "Erro: produto invalido na linha %zu.\n", physical_line);
            csv_free_fields(fields, PRODUCT_FIELD_COUNT);
            goto cleanup;
        }
        csv_free_fields(fields, PRODUCT_FIELD_COUNT);

        if (!append_product(array, &product)) {
            fprintf(stderr, "Erro: memoria insuficiente ao carregar a linha %zu.\n", physical_line);
            product_release(&product);
            goto cleanup;
        }
    }

    if (read_status < 0) {
        fprintf(stderr, "Erro de leitura ou memoria ao processar %s.\n", path);
        goto cleanup;
    }

    success = 1;

cleanup:
    csv_free_fields(fields, PRODUCT_FIELD_COUNT);
    free(line);
    if (fclose(file) != 0 && success) {
        fprintf(stderr, "Erro ao fechar %s.\n", path);
        success = 0;
    }
    if (!success) {
        product_array_free(array);
    }
    return success;
}
