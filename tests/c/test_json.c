#include "unity.h"
#include "json.h"

#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ---------------------------------------------------------------------
 * json_write_string
 * ------------------------------------------------------------------- */

static char *written_to_string(const char *value)
{
    FILE *file = tmpfile();
    long size;
    char *buffer;

    TEST_ASSERT_NOT_NULL(file);
    json_write_string(file, value);

    size = ftell(file);
    TEST_ASSERT_TRUE(size >= 0);

    buffer = malloc((size_t)size + 1U);
    TEST_ASSERT_NOT_NULL(buffer);
    rewind(file);
    TEST_ASSERT_EQUAL_size_t((size_t)size, fread(buffer, 1U, (size_t)size, file));
    buffer[size] = '\0';

    fclose(file);
    return buffer;
}

static void test_write_string_sem_caracteres_especiais(void)
{
    char *written = written_to_string("OpenSSL");

    TEST_ASSERT_EQUAL_STRING("\"OpenSSL\"", written);
    free(written);
}

static void test_write_string_escapa_aspas_e_barra_invertida(void)
{
    char *written = written_to_string("a\"b\\c");

    TEST_ASSERT_EQUAL_STRING("\"a\\\"b\\\\c\"", written);
    free(written);
}

static void test_write_string_escapa_quebra_de_linha_e_tab(void)
{
    char *written = written_to_string("a\nb\tc");

    TEST_ASSERT_EQUAL_STRING("\"a\\nb\\tc\"", written);
    free(written);
}

static void test_write_string_escapa_caractere_de_controle_generico(void)
{
    char value[2] = { '\x01', '\0' };
    char *written = written_to_string(value);

    TEST_ASSERT_EQUAL_STRING("\"\\u0001\"", written);
    free(written);
}

/* ---------------------------------------------------------------------
 * json_skip_whitespace / json_consume_char
 * ------------------------------------------------------------------- */

static void test_skip_whitespace_avanca_ate_caractere_nao_branco(void)
{
    JsonReader reader;

    json_reader_init(&reader, "   \t\n x", 7U);
    json_skip_whitespace(&reader);

    TEST_ASSERT_EQUAL_size_t(6U, reader.pos);
}

static void test_consume_char_bate_e_avanca(void)
{
    JsonReader reader;

    json_reader_init(&reader, "  {resto", 8U);

    TEST_ASSERT_TRUE(json_consume_char(&reader, '{'));
    TEST_ASSERT_EQUAL_size_t(3U, reader.pos);
}

static void test_consume_char_nao_bate_nao_avanca(void)
{
    JsonReader reader;

    json_reader_init(&reader, "  [resto", 8U);

    TEST_ASSERT_FALSE(json_consume_char(&reader, '{'));
    TEST_ASSERT_EQUAL_size_t(2U, reader.pos); /* so' pulou os espacos */
}

/* ---------------------------------------------------------------------
 * json_read_string
 * ------------------------------------------------------------------- */

static void test_read_string_simples(void)
{
    JsonReader reader;
    char *value = NULL;

    json_reader_init(&reader, "\"OpenSSL\" resto", 15U);

    TEST_ASSERT_TRUE(json_read_string(&reader, &value));
    TEST_ASSERT_EQUAL_STRING("OpenSSL", value);
    TEST_ASSERT_EQUAL_size_t(9U, reader.pos); /* logo apos a aspas final */

    free(value);
}

static void test_read_string_com_escapes(void)
{
    static const char *const input = "\"a\\\"b\\\\c\\nd\"";
    JsonReader reader;
    char *value = NULL;

    json_reader_init(&reader, input, strlen(input));

    TEST_ASSERT_TRUE(json_read_string(&reader, &value));
    TEST_ASSERT_EQUAL_STRING("a\"b\\c\nd", value);

    free(value);
}

static void test_read_string_com_u_escape_de_controle(void)
{
    static const char *const input = "\"\\u0001\"";
    JsonReader reader;
    char *value = NULL;
    char expected[2] = { '\x01', '\0' };

    json_reader_init(&reader, input, strlen(input));

    TEST_ASSERT_TRUE(json_read_string(&reader, &value));
    TEST_ASSERT_EQUAL_STRING(expected, value);

    free(value);
}

static void test_read_string_nao_terminada_falha(void)
{
    static const char *const input = "\"sem fechar";
    JsonReader reader;
    char *value = NULL;

    json_reader_init(&reader, input, strlen(input));

    TEST_ASSERT_FALSE(json_read_string(&reader, &value));
}

static void test_read_string_sem_aspas_de_abertura_falha(void)
{
    static const char *const input = "abc\"";
    JsonReader reader;
    char *value = NULL;

    json_reader_init(&reader, input, strlen(input));

    TEST_ASSERT_FALSE(json_read_string(&reader, &value));
}

/* ---------------------------------------------------------------------
 * json_read_uint32
 * ------------------------------------------------------------------- */

static void test_read_uint32_simples(void)
{
    JsonReader reader;
    uint32_t value = 0U;

    json_reader_init(&reader, "2025resto", 9U);

    TEST_ASSERT_TRUE(json_read_uint32(&reader, &value));
    TEST_ASSERT_EQUAL_UINT32(2025U, value);
    TEST_ASSERT_EQUAL_size_t(4U, reader.pos);
}

static void test_read_uint32_pula_espacos_antes(void)
{
    JsonReader reader;
    uint32_t value = 0U;

    json_reader_init(&reader, "   42", 5U);

    TEST_ASSERT_TRUE(json_read_uint32(&reader, &value));
    TEST_ASSERT_EQUAL_UINT32(42U, value);
}

static void test_read_uint32_sem_digitos_falha(void)
{
    JsonReader reader;
    uint32_t value = 0U;

    json_reader_init(&reader, "abc", 3U);

    TEST_ASSERT_FALSE(json_read_uint32(&reader, &value));
}

/* ---------------------------------------------------------------------
 * round-trip: json_write_string seguido de json_read_string
 * ------------------------------------------------------------------- */

static void test_round_trip_write_depois_read(void)
{
    static const char *const original = "Produto \"X\", linha 1\nlinha 2\\fim";
    char *written = written_to_string(original);
    JsonReader reader;
    char *read_back = NULL;

    json_reader_init(&reader, written, strlen(written));
    TEST_ASSERT_TRUE(json_read_string(&reader, &read_back));
    TEST_ASSERT_EQUAL_STRING(original, read_back);

    free(written);
    free(read_back);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_write_string_sem_caracteres_especiais);
    RUN_TEST(test_write_string_escapa_aspas_e_barra_invertida);
    RUN_TEST(test_write_string_escapa_quebra_de_linha_e_tab);
    RUN_TEST(test_write_string_escapa_caractere_de_controle_generico);

    RUN_TEST(test_skip_whitespace_avanca_ate_caractere_nao_branco);
    RUN_TEST(test_consume_char_bate_e_avanca);
    RUN_TEST(test_consume_char_nao_bate_nao_avanca);

    RUN_TEST(test_read_string_simples);
    RUN_TEST(test_read_string_com_escapes);
    RUN_TEST(test_read_string_com_u_escape_de_controle);
    RUN_TEST(test_read_string_nao_terminada_falha);
    RUN_TEST(test_read_string_sem_aspas_de_abertura_falha);

    RUN_TEST(test_read_uint32_simples);
    RUN_TEST(test_read_uint32_pula_espacos_antes);
    RUN_TEST(test_read_uint32_sem_digitos_falha);

    RUN_TEST(test_round_trip_write_depois_read);

    return UNITY_END();
}
