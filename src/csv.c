#include "csv.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define INITIAL_LINE_CAPACITY 4096U

static int grow_buffer(char **buffer, size_t *capacity, size_t required)
{
    size_t new_capacity;
    char *resized;

    if (required <= *capacity) {
        return 1;
    }

    new_capacity = *capacity == 0U ? INITIAL_LINE_CAPACITY : *capacity;
    while (new_capacity < required) {
        if (new_capacity > SIZE_MAX / 2U) {
            return 0;
        }
        new_capacity *= 2U;
    }

    resized = realloc(*buffer, new_capacity);
    if (resized == NULL) {
        return 0;
    }

    *buffer = resized;
    *capacity = new_capacity;
    return 1;
}

int csv_read_line(
    FILE *file,
    char **buffer,
    size_t *capacity,
    size_t *length
)
{
    int character;

    *length = 0U;
    while ((character = fgetc(file)) != EOF) {
        if (!grow_buffer(buffer, capacity, *length + 2U)) {
            return -1;
        }

        if (character == '\n') {
            break;
        }

        (*buffer)[*length] = (char)character;
        ++(*length);
    }

    if (ferror(file)) {
        return -1;
    }
    if (character == EOF && *length == 0U) {
        return 0;
    }
    if (!grow_buffer(buffer, capacity, *length + 1U)) {
        return -1;
    }

    if (*length > 0U && (*buffer)[*length - 1U] == '\r') {
        --(*length);
    }
    (*buffer)[*length] = '\0';
    return 1;
}

static char *duplicate_field(const char *value, size_t length)
{
    char *copy = malloc(length + 1U);

    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, value, length);
    copy[length] = '\0';
    return copy;
}

void csv_free_fields(char **fields, size_t field_count)
{
    size_t index;

    for (index = 0; index < field_count; ++index) {
        free(fields[index]);
        fields[index] = NULL;
    }
}

int csv_parse_line(
    const char *line,
    char **fields,
    size_t expected_field_count
)
{
    size_t line_length = strlen(line);
    char *field_buffer = malloc(line_length + 1U);
    size_t input_index = 0U;
    size_t output_length = 0U;
    size_t field_count = 0U;
    int in_quotes = 0;
    int after_closing_quote = 0;
    int success = 0;

    if (field_buffer == NULL) {
        return 0;
    }

    while (1) {
        char character = line[input_index];

        if (in_quotes) {
            if (character == '\0') {
                goto cleanup;
            }
            if (character == '"') {
                if (line[input_index + 1U] == '"') {
                    field_buffer[output_length++] = '"';
                    input_index += 2U;
                } else {
                    in_quotes = 0;
                    after_closing_quote = 1;
                    ++input_index;
                }
            } else {
                field_buffer[output_length++] = character;
                ++input_index;
            }
            continue;
        }

        if (after_closing_quote) {
            if (character != ',' && character != '\0') {
                goto cleanup;
            }
        } else if (character == '"' && output_length == 0U) {
            in_quotes = 1;
            ++input_index;
            continue;
        } else if (character != ',' && character != '\0') {
            if (character == '"') {
                goto cleanup;
            }
            field_buffer[output_length++] = character;
            ++input_index;
            continue;
        }

        if (field_count >= expected_field_count) {
            goto cleanup;
        }
        fields[field_count] = duplicate_field(field_buffer, output_length);
        if (fields[field_count] == NULL) {
            goto cleanup;
        }
        ++field_count;
        output_length = 0U;
        after_closing_quote = 0;

        if (character == '\0') {
            break;
        }
        ++input_index;
    }

    success = field_count == expected_field_count;

cleanup:
    free(field_buffer);
    if (!success) {
        /* Libera so' o que esta chamada realmente alocou (field_count),
         * nao expected_field_count: entradas de fields ainda nao
         * preenchidas nao sao tocadas, entao o chamador nao precisa
         * pre-zerar o array. */
        csv_free_fields(fields, field_count);
    }
    return success;
}

int csv_header_matches(
    char *const *fields,
    const char *const *expected,
    size_t field_count
)
{
    size_t index;

    for (index = 0U; index < field_count; ++index) {
        if (strcmp(fields[index], expected[index]) != 0) {
            return 0;
        }
    }

    return 1;
}

char *csv_decode_text(const char *encoded)
{
    size_t input_index;
    size_t output_index = 0U;
    size_t length = strlen(encoded);
    char *decoded = malloc(length + 1U);

    if (decoded == NULL) {
        return NULL;
    }

    for (input_index = 0U; input_index < length; ++input_index) {
        if (encoded[input_index] != '\\') {
            decoded[output_index++] = encoded[input_index];
            continue;
        }

        ++input_index;
        if (input_index >= length) {
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
        if (encoded[input_index] == 'n') {
            decoded[output_index++] = '\n';
        } else if (encoded[input_index] == '\\') {
            decoded[output_index++] = '\\';
        } else {
            free(decoded);
            errno = EINVAL;
            return NULL;
        }
    }

    decoded[output_index] = '\0';
    return decoded;
}
