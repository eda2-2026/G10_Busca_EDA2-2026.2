#ifndef JSON_H
#define JSON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


void json_write_string(FILE *file, const char *value);

/* Cursor de leitura sobre um buffer JSON inteiro em memoria (nao um
 * parser de streaming). */
typedef struct {
    const char *data;
    size_t length;
    size_t pos;
} JsonReader;

void json_reader_init(JsonReader *reader, const char *data, size_t length);

/* Avanca o cursor por espacos em branco */
void json_skip_whitespace(JsonReader *reader);

/* Pula espacos e, se o proximo caractere for exatamente `expected` */
int json_consume_char(JsonReader *reader, char expected);

/* Pula espacos e le uma string JSON entre aspas, com escapes \" \\ \/ \n
 * \r \t \b \f e \u00XX. Retorna 1 em sucesso. */
int json_read_string(JsonReader *reader, char **out_value);

/* Pula espacos e le uma sequencia de digitos decimais como uint32_t. Retorna 0 se nao houver nenhum digito
 * ou se o valor estourar UINT32_MAX. */
int json_read_uint32(JsonReader *reader, uint32_t *out_value);

#endif
