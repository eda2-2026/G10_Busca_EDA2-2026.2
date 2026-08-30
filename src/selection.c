#include "selection.h"
#include "json.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define INITIAL_ARRAY_CAPACITY 16U

static void free_string_array(char **items, size_t count)
{
    size_t index;

    for (index = 0U; index < count; ++index) {
        free(items[index]);
    }
    free(items);
}

static void selection_release(Selection *selection)
{
    if (selection == NULL) {
        return;
    }

    free(selection->cve_id);
    free_string_array(selection->products, selection->product_count);
    *selection = (Selection){0};
}

void selection_array_free(SelectionArray *array)
{
    size_t index;

    if (array == NULL) {
        return;
    }

    for (index = 0U; index < array->count; ++index) {
        selection_release(&array->items[index]);
    }

    free(array->items);
    *array = (SelectionArray){0};
}

static int append_selection(SelectionArray *array, Selection *selection)
{
    Selection *resized;
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

    array->items[array->count++] = *selection;
    *selection = (Selection){0};
    return 1;
}

static char *duplicate_c_string(const char *value)
{
    size_t length = strlen(value) + 1U;
    char *copy = malloc(length);

    if (copy != NULL) {
        memcpy(copy, value, length);
    }
    return copy;
}

/* ---------------------------------------------------------------------
 * Leitura (JSON -> SelectionArray)
 * ------------------------------------------------------------------- */

static int parse_product_array(JsonReader *reader, Selection *selection)
{
    char **items = NULL;
    size_t count = 0U;
    size_t capacity = 0U;

    if (!json_consume_char(reader, '[')) {
        return 0;
    }

    json_skip_whitespace(reader);
    if (json_consume_char(reader, ']')) {
        selection->products = NULL;
        selection->product_count = 0U;
        return 1;
    }

    while (1) {
        char *value = NULL;

        if (!json_read_string(reader, &value)) {
            free_string_array(items, count);
            return 0;
        }

        if (count == capacity) {
            size_t new_capacity = capacity == 0U ? 4U : capacity * 2U;
            char **resized = realloc(items, new_capacity * sizeof(*items));

            if (resized == NULL) {
                free(value);
                free_string_array(items, count);
                return 0;
            }
            items = resized;
            capacity = new_capacity;
        }
        items[count++] = value;

        json_skip_whitespace(reader);
        if (json_consume_char(reader, ',')) {
            continue;
        }
        if (json_consume_char(reader, ']')) {
            break;
        }

        free_string_array(items, count);
        return 0;
    }

    selection->products = items;
    selection->product_count = count;
    return 1;
}

/* Analisa um objeto JSON { "cve_id": ..., "year": ..., "state": ...,
 * "products": [...] } - os 4 campos podem vir em qualquer ordem, mas
 * todos sao obrigatorios. Em sucesso, ja' anexa o resultado a `array`. */
static int parse_one_selection(JsonReader *reader, SelectionArray *array)
{
    Selection selection = {0};
    char *key = NULL;
    char *state_text = NULL;
    int has_cve_id = 0;
    int has_year = 0;
    int has_state = 0;
    int has_products = 0;

    if (!json_consume_char(reader, '{')) {
        return 0;
    }

    json_skip_whitespace(reader);
    if (json_consume_char(reader, '}')) {
        return 0; /* objeto vazio: faltam campos obrigatorios */
    }

    while (1) {
        if (!json_read_string(reader, &key) || !json_consume_char(reader, ':')) {
            goto fail;
        }

        if (strcmp(key, "cve_id") == 0 && !has_cve_id) {
            free(key);
            key = NULL;
            if (!json_read_string(reader, &selection.cve_id)) {
                goto fail;
            }
            has_cve_id = 1;
        } else if (strcmp(key, "year") == 0 && !has_year) {
            free(key);
            key = NULL;
            if (!json_read_uint32(reader, &selection.year)) {
                goto fail;
            }
            has_year = 1;
        } else if (strcmp(key, "state") == 0 && !has_state) {
            free(key);
            key = NULL;
            if (!json_read_string(reader, &state_text)) {
                goto fail;
            }
            if (strcmp(state_text, "PUBLISHED") == 0) {
                selection.state = CVE_STATE_PUBLISHED;
            } else if (strcmp(state_text, "REJECTED") == 0) {
                selection.state = CVE_STATE_REJECTED;
            } else {
                goto fail;
            }
            free(state_text);
            state_text = NULL;
            has_state = 1;
        } else if (strcmp(key, "products") == 0 && !has_products) {
            free(key);
            key = NULL;
            if (!parse_product_array(reader, &selection)) {
                goto fail;
            }
            has_products = 1;
        } else {
            goto fail; /* campo desconhecido ou duplicado */
        }

        json_skip_whitespace(reader);
        if (json_consume_char(reader, ',')) {
            continue;
        }
        if (json_consume_char(reader, '}')) {
            break;
        }
        goto fail;
    }

    if (!has_cve_id || !has_year || !has_state || !has_products) {
        goto fail;
    }
    if (!append_selection(array, &selection)) {
        goto fail;
    }

    return 1;

fail:
    free(key);
    free(state_text);
    selection_release(&selection);
    return 0;
}

static int read_entire_file(const char *path, char **out_data, size_t *out_length)
{
    FILE *file = fopen(path, "rb");
    long size;
    char *buffer;

    if (file == NULL) {
        return errno == ENOENT ? 0 : -1;
    }

    if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0
        || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return -1;
    }

    buffer = malloc((size_t)size + 1U);
    if (buffer == NULL) {
        fclose(file);
        return -1;
    }

    if (size > 0 && fread(buffer, 1U, (size_t)size, file) != (size_t)size) {
        free(buffer);
        fclose(file);
        return -1;
    }
    buffer[size] = '\0';
    fclose(file);

    *out_data = buffer;
    *out_length = (size_t)size;
    return 1;
}

int selection_array_load_json(SelectionArray *array, const char *path)
{
    char *data = NULL;
    size_t length = 0U;
    int read_status;
    JsonReader reader;

    if (array == NULL || path == NULL
        || array->items != NULL || array->count != 0U || array->capacity != 0U) {
        fprintf(stderr, "Erro: argumentos invalidos para carregar selecoes.\n");
        return 0;
    }

    read_status = read_entire_file(path, &data, &length);
    if (read_status == 0) {
        return 1; /* ainda nao existe: comeca vazio, nao e' erro */
    }
    if (read_status < 0) {
        fprintf(stderr, "Erro ao ler %s: %s\n", path, strerror(errno));
        return 0;
    }

    json_reader_init(&reader, data, length);

    if (!json_consume_char(&reader, '[')) {
        goto parse_error;
    }
    json_skip_whitespace(&reader);
    if (!json_consume_char(&reader, ']')) {
        while (1) {
            if (!parse_one_selection(&reader, array)) {
                goto parse_error;
            }
            json_skip_whitespace(&reader);
            if (json_consume_char(&reader, ',')) {
                continue;
            }
            if (json_consume_char(&reader, ']')) {
                break;
            }
            goto parse_error;
        }
    }

    free(data);
    return 1;

parse_error:
    fprintf(stderr, "Erro: %s contem JSON invalido.\n", path);
    free(data);
    selection_array_free(array);
    return 0;
}

/* ---------------------------------------------------------------------
 * Escrita (SelectionArray -> JSON)
 * ------------------------------------------------------------------- */

static void ensure_parent_directory_exists(const char *path)
{
    const char *last_slash = strrchr(path, '/');
    char *dir;

    if (last_slash == NULL) {
        return; /* caminho sem diretorio: nada a criar */
    }

    dir = malloc((size_t)(last_slash - path) + 1U);
    if (dir == NULL) {
        return; /* se falhar, fopen abaixo vai reportar o erro real */
    }
    memcpy(dir, path, (size_t)(last_slash - path));
    dir[last_slash - path] = '\0';

    mkdir(dir, 0755); /* ignora erro (ex.: ja' existe); fopen reporta depois */

    free(dir);
}

int selection_array_save_json(const SelectionArray *array, const char *path)
{
    size_t tmp_path_length;
    char *tmp_path;
    FILE *file;
    size_t index;
    int success;

    if (array == NULL || path == NULL) {
        return 0;
    }

    ensure_parent_directory_exists(path);

    tmp_path_length = strlen(path) + 5U; /* ".tmp" + '\0' */
    tmp_path = malloc(tmp_path_length);
    if (tmp_path == NULL) {
        return 0;
    }
    snprintf(tmp_path, tmp_path_length, "%s.tmp", path);

    file = fopen(tmp_path, "wb");
    if (file == NULL) {
        fprintf(stderr, "Erro ao abrir %s: %s\n", tmp_path, strerror(errno));
        free(tmp_path);
        return 0;
    }

    fputs("[\n", file);
    for (index = 0U; index < array->count; ++index) {
        const Selection *selection = &array->items[index];
        size_t product_index;

        fputs("  {\n    \"cve_id\": ", file);
        json_write_string(file, selection->cve_id);
        fprintf(file, ",\n    \"year\": %" PRIu32 ",\n    \"state\": ", selection->year);
        json_write_string(
            file,
            selection->state == CVE_STATE_PUBLISHED ? "PUBLISHED" : "REJECTED"
        );
        fputs(",\n    \"products\": [", file);
        for (product_index = 0U; product_index < selection->product_count; ++product_index) {
            if (product_index > 0U) {
                fputs(", ", file);
            }
            json_write_string(file, selection->products[product_index]);
        }
        fputs("]\n  }", file);
        fputs(index + 1U < array->count ? ",\n" : "\n", file);
    }
    fputs("]\n", file);

    success = !ferror(file);
    if (fclose(file) != 0) {
        success = 0;
    }

    if (success && rename(tmp_path, path) != 0) {
        fprintf(stderr, "Erro ao mover %s para %s: %s\n", tmp_path, path, strerror(errno));
        success = 0;
    }
    if (!success) {
        remove(tmp_path);
    }

    free(tmp_path);
    return success;
}

/* ---------------------------------------------------------------------
 * selection_array_upsert
 * ------------------------------------------------------------------- */

int selection_array_upsert(
    SelectionArray *array,
    const char *cve_id,
    uint32_t year,
    CVEState state,
    char *const *products,
    size_t product_count
)
{
    Selection new_selection = {0};
    char **products_copy = NULL;
    size_t index;
    size_t existing_index = 0U;
    int already_exists = 0;

    if (array == NULL || cve_id == NULL) {
        return 0;
    }

    for (index = 0U; index < array->count; ++index) {
        if (strcmp(array->items[index].cve_id, cve_id) == 0) {
            already_exists = 1;
            existing_index = index;
            break;
        }
    }

    if (product_count > 0U) {
        products_copy = malloc(product_count * sizeof(*products_copy));
        if (products_copy == NULL) {
            return 0;
        }
        for (index = 0U; index < product_count; ++index) {
            products_copy[index] = duplicate_c_string(products[index]);
            if (products_copy[index] == NULL) {
                free_string_array(products_copy, index);
                return 0;
            }
        }
    }

    new_selection.cve_id = duplicate_c_string(cve_id);
    if (new_selection.cve_id == NULL) {
        free_string_array(products_copy, product_count);
        return 0;
    }
    new_selection.year = year;
    new_selection.state = state;
    new_selection.products = products_copy;
    new_selection.product_count = product_count;

    if (already_exists) {
        selection_release(&array->items[existing_index]);
        array->items[existing_index] = new_selection;
        return 1;
    }

    if (!append_selection(array, &new_selection)) {
        selection_release(&new_selection);
        return 0;
    }

    return 1;
}
