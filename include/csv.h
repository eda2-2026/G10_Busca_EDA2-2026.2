#ifndef CSV_H
#define CSV_H

#include <stddef.h>
#include <stdio.h>

/* Retorna 1 se leu uma linha, 0 em EOF sem nenhum dado lido, -1 em erro de
 * leitura ou de memoria. */
int csv_read_line(
    FILE *file,
    char **buffer,
    size_t *capacity,
    size_t *length
);

/* Interpreta uma linha CSV em exatamente `expected_field_count`
 * campos alocados dinamicamente em `fields`.
 *
 * Em caso de erro (numero de campos diferente do esperado, aspas mal
 * formadas, etc.) a funcao libera os campos que ela mesma alocou antes de
 * falhar*/
int csv_parse_line(
    const char *line,
    char **fields,
    size_t expected_field_count
);

/* Libera fields[0..field_count-1] (ignora ponteiros NULL) e os zera. */
void csv_free_fields(char **fields, size_t field_count);

/* Retorna 1 se os primeiros field_count elementos de `fields` sao,
 * em ordem, exatamente iguais (strcmp) aos nomes em `expected`. */
int csv_header_matches(
    char *const *fields,
    const char *const *expected,
    size_t field_count
);

/* Desfaz a codificacao de texto-de-uma-linha usada pelo gerador Python:
 * a sequencia de duas caracteres "\n" (barra invertida seguida de 'n')
 * volta a ser uma quebra de linha real, e "\\" volta a ser uma unica barra
 * invertida. Qualquer outra sequencia iniciada por '\' e' invalida.
 */
char *csv_decode_text(const char *encoded);

#endif
