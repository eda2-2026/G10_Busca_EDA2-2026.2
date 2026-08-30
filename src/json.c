#include "json.h"

#include <stdint.h>
#include <stdlib.h>

void json_write_string(FILE *file, const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    fputc('"', file);
    for (; *cursor != '\0'; ++cursor) {
        switch (*cursor) {
            case '"':
                fputs("\\\"", file);
                break;
            case '\\':
                fputs("\\\\", file);
                break;
            case '\n':
                fputs("\\n", file);
                break;
            case '\r':
                fputs("\\r", file);
                break;
            case '\t':
                fputs("\\t", file);
                break;
            default:
                if (*cursor < 0x20U) {
                    fprintf(file, "\\u%04x", (unsigned int)*cursor);
                } else {
                    fputc((int)*cursor, file);
                }
                break;
        }
    }
    fputc('"', file);
}

void json_reader_init(JsonReader *reader, const char *data, size_t length)
{
    reader->data = data;
    reader->length = length;
    reader->pos = 0U;
}

void json_skip_whitespace(JsonReader *reader)
{
    while (reader->pos < reader->length) {
        char character = reader->data[reader->pos];

        if (character != ' ' && character != '\t'
            && character != '\n' && character != '\r') {
            break;
        }
        ++reader->pos;
    }
}

int json_consume_char(JsonReader *reader, char expected)
{
    json_skip_whitespace(reader);

    if (reader->pos < reader->length && reader->data[reader->pos] == expected) {
        ++reader->pos;
        return 1;
    }

    return 0;
}

int json_read_string(JsonReader *reader, char **out_value)
{
    size_t max_length;
    char *buffer;
    size_t length = 0U;

    if (!json_consume_char(reader, '"')) {
        return 0;
    }

    max_length = reader->length - reader->pos;
    buffer = malloc(max_length + 1U);
    if (buffer == NULL) {
        return 0;
    }

    while (1) {
        char character;

        if (reader->pos >= reader->length) {
            free(buffer);
            return 0; /* string nao terminada */
        }

        character = reader->data[reader->pos];

        if (character == '"') {
            ++reader->pos;
            break;
        }

        if (character != '\\') {
            buffer[length++] = character;
            ++reader->pos;
            continue;
        }

        ++reader->pos;
        if (reader->pos >= reader->length) {
            free(buffer);
            return 0;
        }

        switch (reader->data[reader->pos]) {
            case '"':
                buffer[length++] = '"';
                ++reader->pos;
                break;
            case '\\':
                buffer[length++] = '\\';
                ++reader->pos;
                break;
            case '/':
                buffer[length++] = '/';
                ++reader->pos;
                break;
            case 'n':
                buffer[length++] = '\n';
                ++reader->pos;
                break;
            case 'r':
                buffer[length++] = '\r';
                ++reader->pos;
                break;
            case 't':
                buffer[length++] = '\t';
                ++reader->pos;
                break;
            case 'b':
                buffer[length++] = '\b';
                ++reader->pos;
                break;
            case 'f':
                buffer[length++] = '\f';
                ++reader->pos;
                break;
            case 'u': {
                unsigned int codepoint;
                size_t digits_start = reader->pos + 1U;

                if (digits_start + 4U > reader->length
                    || sscanf(reader->data + digits_start, "%4x", &codepoint) != 1
                    || codepoint > 0xFFU) {
                    free(buffer);
                    return 0; /* fora do que este leitor suporta */
                }
                buffer[length++] = (char)codepoint;
                reader->pos += 5U; /* 'u' + 4 digitos hex */
                break;
            }
            default:
                free(buffer);
                return 0;
        }
    }

    buffer[length] = '\0';
    *out_value = buffer;
    return 1;
}

int json_read_uint32(JsonReader *reader, uint32_t *out_value)
{
    uint32_t value = 0U;
    size_t digit_count = 0U;

    json_skip_whitespace(reader);

    while (reader->pos < reader->length
        && reader->data[reader->pos] >= '0'
        && reader->data[reader->pos] <= '9') {
        uint32_t digit = (uint32_t)(reader->data[reader->pos] - '0');

        if (value > (UINT32_MAX - digit) / 10U) {
            return 0; /* overflow */
        }
        value = value * 10U + digit;
        ++reader->pos;
        ++digit_count;
    }

    if (digit_count == 0U) {
        return 0;
    }

    *out_value = value;
    return 1;
}
