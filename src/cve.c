#include "cve.h"
#include "csv.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CVE_FIELD_COUNT 5U
#define INITIAL_ARRAY_CAPACITY 1024U

static void cve_release(CVE *cve)
{
    if (cve == NULL) {
        return;
    }

    free(cve->cve_id);
    free(cve->description_en);
    free(cve->title);
    free(cve->rejection_reason_en);
    *cve = (CVE){0};
}

void cve_array_free(CVEArray *array)
{
    size_t index;

    if (array == NULL) {
        return;
    }

    for (index = 0; index < array->count; ++index) {
        cve_release(&array->items[index]);
    }

    free(array->items);
    *array = (CVEArray){0};
}

int cve_compare_key(const CVE *left, const CVE *right)
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

int cve_array_is_sorted_by_key(const CVEArray *array)
{
    size_t index;

    if (array == NULL || (array->count > 0U && array->items == NULL)) {
        return 0;
    }

    for (index = 1U; index < array->count; ++index) {
        if (cve_compare_key(&array->items[index - 1U], &array->items[index]) > 0) {
            return 0;
        }
    }

    return 1;
}

static int parse_decimal_u32(
    const char *digits,
    size_t length,
    uint32_t *result
)
{
    uint32_t value = 0U;
    size_t index;

    if (length == 0U || result == NULL) {
        return 0;
    }

    for (index = 0U; index < length; ++index) {
        uint32_t digit;

        if (digits[index] < '0' || digits[index] > '9') {
            return 0;
        }
        digit = (uint32_t)(digits[index] - '0');
        if (value > (UINT32_MAX - digit) / 10U) {
            return 0;
        }
        value = value * 10U + digit;
    }

    *result = value;
    return 1;
}

int cve_parse_key(
    const char *cve_id,
    uint32_t *year,
    uint32_t *number
)
{
    size_t length;
    size_t number_length;

    if (cve_id == NULL || year == NULL || number == NULL) {
        return 0;
    }

    length = strlen(cve_id);
    if (length < 13U
        || strncmp(cve_id, "CVE-", 4U) != 0
        || cve_id[8] != '-') {
        return 0;
    }

    number_length = length - 9U;
    if (number_length < 4U
        || (number_length > 4U && cve_id[9] == '0')
        || !parse_decimal_u32(cve_id + 4U, 4U, year)
        || !parse_decimal_u32(cve_id + 9U, number_length, number)
        || *year == 0U
        || *number == 0U) {
        return 0;
    }

    return 1;
}

static int build_cve(char **fields, CVE *cve)
{
    if (!cve_parse_key(fields[0], &cve->year, &cve->number)) {
        return 0;
    }

    if (strcmp(fields[1], "PUBLISHED") == 0) {
        cve->state = CVE_STATE_PUBLISHED;
    } else if (strcmp(fields[1], "REJECTED") == 0) {
        cve->state = CVE_STATE_REJECTED;
    } else {
        return 0;
    }

    cve->cve_id = fields[0];
    fields[0] = NULL;
    cve->description_en = csv_decode_text(fields[2]);
    cve->title = csv_decode_text(fields[3]);
    cve->rejection_reason_en = csv_decode_text(fields[4]);

    if (cve->description_en == NULL
        || cve->title == NULL
        || cve->rejection_reason_en == NULL) {
        cve_release(cve);
        return 0;
    }

    if (cve->state == CVE_STATE_PUBLISHED) {
        if (cve->description_en[0] == '\0'
            || cve->rejection_reason_en[0] != '\0') {
            cve_release(cve);
            return 0;
        }
    } else if (cve->description_en[0] != '\0'
               || cve->title[0] != '\0'
               || cve->rejection_reason_en[0] == '\0') {
        cve_release(cve);
        return 0;
    }

    return 1;
}

static int append_cve(CVEArray *array, CVE *cve)
{
    CVE *resized;
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

    array->items[array->count++] = *cve;
    *cve = (CVE){0};
    return 1;
}

int cve_array_load_csv(CVEArray *array, const char *path)
{
    static const char *const expected_header[CVE_FIELD_COUNT] = {
        "cve_id",
        "state",
        "description_en",
        "title",
        "rejection_reason_en"
    };
    FILE *file;
    char *line = NULL;
    size_t line_capacity = 0U;
    size_t line_length = 0U;
    size_t physical_line = 0U;
    char *fields[CVE_FIELD_COUNT] = {0};
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
        || !csv_parse_line(line, fields, CVE_FIELD_COUNT)) {
        fprintf(stderr, "Erro: cabecalho CSV ausente ou invalido.\n");
        goto cleanup;
    }
    physical_line = 1U;

    if (!csv_header_matches(fields, expected_header, CVE_FIELD_COUNT)) {
        fprintf(stderr, "Erro: cabecalho inesperado em %s.\n", path);
        goto cleanup;
    }
    csv_free_fields(fields, CVE_FIELD_COUNT);

    while ((read_status = csv_read_line(
                file, &line, &line_capacity, &line_length
            )) == 1) {
        CVE cve = {0};
        ++physical_line;

        if (!csv_parse_line(line, fields, CVE_FIELD_COUNT)) {
            fprintf(stderr, "Erro: CSV malformado na linha %zu.\n", physical_line);
            goto cleanup;
        }
        if (!build_cve(fields, &cve)) {
            fprintf(stderr, "Erro: CVE invalida na linha %zu.\n", physical_line);
            csv_free_fields(fields, CVE_FIELD_COUNT);
            goto cleanup;
        }
        csv_free_fields(fields, CVE_FIELD_COUNT);

        if (!append_cve(array, &cve)) {
            fprintf(stderr, "Erro: memoria insuficiente ao carregar a linha %zu.\n", physical_line);
            cve_release(&cve);
            goto cleanup;
        }
    }

    if (read_status < 0) {
        fprintf(stderr, "Erro de leitura ou memoria ao processar %s.\n", path);
        goto cleanup;
    }

    success = 1;

cleanup:
    csv_free_fields(fields, CVE_FIELD_COUNT);
    free(line);
    if (fclose(file) != 0 && success) {
        fprintf(stderr, "Erro ao fechar %s.\n", path);
        success = 0;
    }
    if (!success) {
        cve_array_free(array);
    }
    return success;
}
