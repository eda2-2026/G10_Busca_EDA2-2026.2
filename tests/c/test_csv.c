#include "unity.h"
#include "csv.h"

#include <stdlib.h>

void setUp(void) {}
void tearDown(void) {}

 * csv_parse_line

static void test_parse_line_campos_simples(void)
{
    char *fields[3] = {0};

    TEST_ASSERT_TRUE(csv_parse_line("a,b,c", fields, 3U));
    TEST_ASSERT_EQUAL_STRING("a", fields[0]);
    TEST_ASSERT_EQUAL_STRING("b", fields[1]);
    TEST_ASSERT_EQUAL_STRING("c", fields[2]);

    csv_free_fields(fields, 3U);
}

static void test_parse_line_campo_vazio_no_meio(void)
{
    char *fields[3] = {0};

    TEST_ASSERT_TRUE(csv_parse_line("a,,c", fields, 3U));
    TEST_ASSERT_EQUAL_STRING("a", fields[0]);
    TEST_ASSERT_EQUAL_STRING("", fields[1]);
    TEST_ASSERT_EQUAL_STRING("c", fields[2]);

    csv_free_fields(fields, 3U);
}

static void test_parse_line_campo_entre_aspas_com_virgula(void)
{
    char *fields[3] = {0};

    TEST_ASSERT_TRUE(csv_parse_line("a,\"b,c\",d", fields, 3U));
    TEST_ASSERT_EQUAL_STRING("a", fields[0]);
    TEST_ASSERT_EQUAL_STRING("b,c", fields[1]);
    TEST_ASSERT_EQUAL_STRING("d", fields[2]);

    csv_free_fields(fields, 3U);
}

static void test_parse_line_aspas_duplicadas_viram_uma_aspas_literal(void)
{
    char *fields[1] = {0};

    TEST_ASSERT_TRUE(csv_parse_line("\"a\"\"b\"", fields, 1U));
    TEST_ASSERT_EQUAL_STRING("a\"b", fields[0]);

    csv_free_fields(fields, 1U);
}

static void test_parse_line_erro_numero_de_campos_diferente(void)
{
    char *fields[3] = {0};

    TEST_ASSERT_FALSE(csv_parse_line("a,b", fields, 3U));
}

static void test_parse_line_erro_aspas_nao_fechadas(void)
{
    char *fields[1] = {0};

    TEST_ASSERT_FALSE(csv_parse_line("\"sem fechar", fields, 1U));
}

static void test_parse_line_erro_caractere_apos_aspas_fechada(void)
{
    char *fields[1] = {0};

    TEST_ASSERT_FALSE(csv_parse_line("\"ok\"x", fields, 1U));
}

static void test_parse_line_erro_aspas_no_meio_de_campo_sem_aspas(void)
{
    char *fields[1] = {0};

    TEST_ASSERT_FALSE(csv_parse_line("ab\"cd", fields, 1U));
}

 * csv_header_matches


static void test_header_matches_quando_igual(void)
{
    char *fields[3] = {0};
    static const char *const expected[3] = {"a", "b", "c"};

    TEST_ASSERT_TRUE(csv_parse_line("a,b,c", fields, 3U));
    TEST_ASSERT_TRUE(csv_header_matches(fields, expected, 3U));

    csv_free_fields(fields, 3U);
}

static void test_header_matches_quando_diferente(void)
{
    char *fields[3] = {0};
    static const char *const expected[3] = {"a", "b", "c"};

    TEST_ASSERT_TRUE(csv_parse_line("a,x,c", fields, 3U));
    TEST_ASSERT_FALSE(csv_header_matches(fields, expected, 3U));

    csv_free_fields(fields, 3U);
}

 * csv_decode_text
 

static void test_decode_text_sem_escapes_fica_igual(void)
{
    char *decoded = csv_decode_text("hello");

    TEST_ASSERT_NOT_NULL(decoded);
    TEST_ASSERT_EQUAL_STRING("hello", decoded);

    free(decoded);
}

static void test_decode_text_barra_n_vira_quebra_de_linha_real(void)
{
    char *decoded = csv_decode_text("line1\\nline2");

    TEST_ASSERT_NOT_NULL(decoded);
    TEST_ASSERT_EQUAL_STRING("line1\nline2", decoded);

    free(decoded);
}

static void test_decode_text_barra_dupla_vira_uma_barra(void)
{
    char *decoded = csv_decode_text("a\\\\b");

    TEST_ASSERT_NOT_NULL(decoded);
    TEST_ASSERT_EQUAL_STRING("a\\b", decoded);

    free(decoded);
}

static void test_decode_text_escape_desconhecido_retorna_null(void)
{
    TEST_ASSERT_NULL(csv_decode_text("a\\xb"));
}

static void test_decode_text_barra_no_final_retorna_null(void)
{
    TEST_ASSERT_NULL(csv_decode_text("abc\\"));
}

 * csv_read_line


static FILE *file_with_content(const char *content)
{
    FILE *file = tmpfile();

    TEST_ASSERT_NOT_NULL(file);
    fputs(content, file);
    rewind(file);
    return file;
}

static void test_read_line_le_uma_linha_terminada_em_lf(void)
{
    FILE *file = file_with_content("abc\n");
    char *buffer = NULL;
    size_t capacity = 0U;
    size_t length = 0U;

    TEST_ASSERT_EQUAL_INT(1, csv_read_line(file, &buffer, &capacity, &length));
    TEST_ASSERT_EQUAL_STRING("abc", buffer);
    TEST_ASSERT_EQUAL_size_t(3U, length);

    free(buffer);
    fclose(file);
}

static void test_read_line_remove_cr_final(void)
{
    FILE *file = file_with_content("abc\r\n");
    char *buffer = NULL;
    size_t capacity = 0U;
    size_t length = 0U;

    TEST_ASSERT_EQUAL_INT(1, csv_read_line(file, &buffer, &capacity, &length));
    TEST_ASSERT_EQUAL_STRING("abc", buffer);

    free(buffer);
    fclose(file);
}

static void test_read_line_varias_linhas_e_eof(void)
{
    FILE *file = file_with_content("um\ndois");
    char *buffer = NULL;
    size_t capacity = 0U;
    size_t length = 0U;

    TEST_ASSERT_EQUAL_INT(1, csv_read_line(file, &buffer, &capacity, &length));
    TEST_ASSERT_EQUAL_STRING("um", buffer);

    /* Ultima linha sem '\n' final ainda conta como linha valida. */
    TEST_ASSERT_EQUAL_INT(1, csv_read_line(file, &buffer, &capacity, &length));
    TEST_ASSERT_EQUAL_STRING("dois", buffer);

    /* Nada mais para ler: EOF sem dados. */
    TEST_ASSERT_EQUAL_INT(0, csv_read_line(file, &buffer, &capacity, &length));

    free(buffer);
    fclose(file);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_parse_line_campos_simples);
    RUN_TEST(test_parse_line_campo_vazio_no_meio);
    RUN_TEST(test_parse_line_campo_entre_aspas_com_virgula);
    RUN_TEST(test_parse_line_aspas_duplicadas_viram_uma_aspas_literal);
    RUN_TEST(test_parse_line_erro_numero_de_campos_diferente);
    RUN_TEST(test_parse_line_erro_aspas_nao_fechadas);
    RUN_TEST(test_parse_line_erro_caractere_apos_aspas_fechada);
    RUN_TEST(test_parse_line_erro_aspas_no_meio_de_campo_sem_aspas);

    RUN_TEST(test_header_matches_quando_igual);
    RUN_TEST(test_header_matches_quando_diferente);

    RUN_TEST(test_decode_text_sem_escapes_fica_igual);
    RUN_TEST(test_decode_text_barra_n_vira_quebra_de_linha_real);
    RUN_TEST(test_decode_text_barra_dupla_vira_uma_barra);
    RUN_TEST(test_decode_text_escape_desconhecido_retorna_null);
    RUN_TEST(test_decode_text_barra_no_final_retorna_null);

    RUN_TEST(test_read_line_le_uma_linha_terminada_em_lf);
    RUN_TEST(test_read_line_remove_cr_final);
    RUN_TEST(test_read_line_varias_linhas_e_eof);

    return UNITY_END();
}
