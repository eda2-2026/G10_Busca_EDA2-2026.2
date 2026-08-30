#include "unity.h"
#include "selection.h"

#include <stdio.h>

void setUp(void) {}

#define FIXTURE_PATH "build/tests/fixture_selection.json"

void tearDown(void)
{
    remove(FIXTURE_PATH);
    remove(FIXTURE_PATH ".tmp");
}

/* ---------------------------------------------------------------------
 * selection_array_load_json
 * ------------------------------------------------------------------- */

static void test_load_json_arquivo_inexistente_comeca_vazio(void)
{
    SelectionArray array = {0};

    TEST_ASSERT_TRUE(selection_array_load_json(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);

    selection_array_free(&array);
}

static void write_fixture(const char *content)
{
    FILE *file = fopen(FIXTURE_PATH, "wb");

    TEST_ASSERT_NOT_NULL(file);
    fputs(content, file);
    fclose(file);
}

static void test_load_json_array_vazio(void)
{
    SelectionArray array = {0};

    write_fixture("[]");

    TEST_ASSERT_TRUE(selection_array_load_json(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);

    selection_array_free(&array);
}

static void test_load_json_um_registro_com_produtos(void)
{
    SelectionArray array = {0};

    write_fixture(
        "[\n"
        "  {\n"
        "    \"cve_id\": \"CVE-2025-0001\",\n"
        "    \"year\": 2025,\n"
        "    \"state\": \"PUBLISHED\",\n"
        "    \"products\": [\"Abacus\", \"Outro\"]\n"
        "  }\n"
        "]\n"
    );

    TEST_ASSERT_TRUE(selection_array_load_json(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(1U, array.count);
    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", array.items[0].cve_id);
    TEST_ASSERT_EQUAL_UINT32(2025U, array.items[0].year);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_PUBLISHED, array.items[0].state);
    TEST_ASSERT_EQUAL_size_t(2U, array.items[0].product_count);
    TEST_ASSERT_EQUAL_STRING("Abacus", array.items[0].products[0]);
    TEST_ASSERT_EQUAL_STRING("Outro", array.items[0].products[1]);

    selection_array_free(&array);
}

static void test_load_json_campos_em_qualquer_ordem(void)
{
    SelectionArray array = {0};

    write_fixture(
        "[{\"products\": [], \"state\": \"REJECTED\", \"cve_id\": \"CVE-2025-0002\", \"year\": 2025}]"
    );

    TEST_ASSERT_TRUE(selection_array_load_json(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(1U, array.count);
    TEST_ASSERT_EQUAL_STRING("CVE-2025-0002", array.items[0].cve_id);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_REJECTED, array.items[0].state);
    TEST_ASSERT_EQUAL_size_t(0U, array.items[0].product_count);

    selection_array_free(&array);
}

static void test_load_json_campo_faltando_falha(void)
{
    SelectionArray array = {0};

    write_fixture("[{\"cve_id\": \"CVE-2025-0001\", \"year\": 2025, \"state\": \"PUBLISHED\"}]");

    TEST_ASSERT_FALSE(selection_array_load_json(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);
}

static void test_load_json_state_invalido_falha(void)
{
    SelectionArray array = {0};

    write_fixture(
        "[{\"cve_id\": \"CVE-2025-0001\", \"year\": 2025, \"state\": \"X\", \"products\": []}]"
    );

    TEST_ASSERT_FALSE(selection_array_load_json(&array, FIXTURE_PATH));
}

static void test_load_json_sem_colchete_de_abertura_falha(void)
{
    SelectionArray array = {0};

    write_fixture("{}");

    TEST_ASSERT_FALSE(selection_array_load_json(&array, FIXTURE_PATH));
}

/* ---------------------------------------------------------------------
 * selection_array_upsert
 * ------------------------------------------------------------------- */

static void test_upsert_insere_novo(void)
{
    SelectionArray array = {0};
    char *products[1] = { (char *)"Abacus" };

    TEST_ASSERT_TRUE(selection_array_upsert(
        &array, "CVE-2025-0001", 2025U, CVE_STATE_PUBLISHED, products, 1U
    ));

    TEST_ASSERT_EQUAL_size_t(1U, array.count);
    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", array.items[0].cve_id);
    TEST_ASSERT_EQUAL_size_t(1U, array.items[0].product_count);
    TEST_ASSERT_EQUAL_STRING("Abacus", array.items[0].products[0]);

    selection_array_free(&array);
}

static void test_upsert_mesma_chave_substitui_sem_duplicar(void)
{
    SelectionArray array = {0};
    char *products_v1[1] = { (char *)"A" };
    char *products_v2[2] = { (char *)"B1", (char *)"B2" };

    TEST_ASSERT_TRUE(selection_array_upsert(
        &array, "CVE-2025-0001", 2025U, CVE_STATE_PUBLISHED, products_v1, 1U
    ));
    TEST_ASSERT_TRUE(selection_array_upsert(
        &array, "CVE-2025-0001", 2025U, CVE_STATE_PUBLISHED, products_v2, 2U
    ));

    TEST_ASSERT_EQUAL_size_t(1U, array.count); /* nao duplicou */
    TEST_ASSERT_EQUAL_size_t(2U, array.items[0].product_count);
    TEST_ASSERT_EQUAL_STRING("B1", array.items[0].products[0]);
    TEST_ASSERT_EQUAL_STRING("B2", array.items[0].products[1]);

    selection_array_free(&array);
}

static void test_upsert_copia_strings_nao_guarda_ponteiros_recebidos(void)
{
    SelectionArray array = {0};
    char cve_id_buffer[] = "CVE-2025-0001";
    char product_buffer[] = "Abacus";
    char *products[1] = { product_buffer };

    TEST_ASSERT_TRUE(selection_array_upsert(
        &array, cve_id_buffer, 2025U, CVE_STATE_PUBLISHED, products, 1U
    ));

    /* Modifica os buffers originais depois do upsert: a copia interna nao
     * deve ser afetada, ja' que selection_array_upsert copia as strings. */
    cve_id_buffer[0] = 'X';
    product_buffer[0] = 'X';

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", array.items[0].cve_id);
    TEST_ASSERT_EQUAL_STRING("Abacus", array.items[0].products[0]);

    selection_array_free(&array);
}

/* ---------------------------------------------------------------------
 * round-trip: upsert -> save -> load
 * ------------------------------------------------------------------- */

static void test_round_trip_save_depois_load(void)
{
    SelectionArray original = {0};
    SelectionArray reloaded = {0};
    char *products_a[2] = { (char *)"Abacus", (char *)"Widget" };

    TEST_ASSERT_TRUE(selection_array_upsert(
        &original, "CVE-2025-0001", 2025U, CVE_STATE_PUBLISHED, products_a, 2U
    ));
    TEST_ASSERT_TRUE(selection_array_upsert(
        &original, "CVE-2025-0099", 2025U, CVE_STATE_REJECTED, NULL, 0U
    ));

    TEST_ASSERT_TRUE(selection_array_save_json(&original, FIXTURE_PATH));

    TEST_ASSERT_TRUE(selection_array_load_json(&reloaded, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(2U, reloaded.count);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", reloaded.items[0].cve_id);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_PUBLISHED, reloaded.items[0].state);
    TEST_ASSERT_EQUAL_size_t(2U, reloaded.items[0].product_count);
    TEST_ASSERT_EQUAL_STRING("Abacus", reloaded.items[0].products[0]);
    TEST_ASSERT_EQUAL_STRING("Widget", reloaded.items[0].products[1]);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0099", reloaded.items[1].cve_id);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_REJECTED, reloaded.items[1].state);
    TEST_ASSERT_EQUAL_size_t(0U, reloaded.items[1].product_count);

    selection_array_free(&original);
    selection_array_free(&reloaded);
}

static void test_round_trip_preserva_caracteres_especiais_no_produto(void)
{
    SelectionArray original = {0};
    SelectionArray reloaded = {0};
    char *products[1] = { (char *)"Nome \"com\" aspas,\nvirgula e quebra" };

    TEST_ASSERT_TRUE(selection_array_upsert(
        &original, "CVE-2025-0001", 2025U, CVE_STATE_PUBLISHED, products, 1U
    ));
    TEST_ASSERT_TRUE(selection_array_save_json(&original, FIXTURE_PATH));
    TEST_ASSERT_TRUE(selection_array_load_json(&reloaded, FIXTURE_PATH));

    TEST_ASSERT_EQUAL_STRING(
        "Nome \"com\" aspas,\nvirgula e quebra", reloaded.items[0].products[0]
    );

    selection_array_free(&original);
    selection_array_free(&reloaded);
}

static void test_save_cria_diretorio_pai_se_nao_existir(void)
{
    SelectionArray array = {0};
    SelectionArray reloaded = {0};
    static const char *const path = "build/tests/subdir_nao_existente/selections.json";

    TEST_ASSERT_TRUE(selection_array_upsert(
        &array, "CVE-2025-0001", 2025U, CVE_STATE_PUBLISHED, NULL, 0U
    ));
    TEST_ASSERT_TRUE(selection_array_save_json(&array, path));
    TEST_ASSERT_TRUE(selection_array_load_json(&reloaded, path));
    TEST_ASSERT_EQUAL_size_t(1U, reloaded.count);

    remove(path);
    selection_array_free(&array);
    selection_array_free(&reloaded);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_load_json_arquivo_inexistente_comeca_vazio);
    RUN_TEST(test_load_json_array_vazio);
    RUN_TEST(test_load_json_um_registro_com_produtos);
    RUN_TEST(test_load_json_campos_em_qualquer_ordem);
    RUN_TEST(test_load_json_campo_faltando_falha);
    RUN_TEST(test_load_json_state_invalido_falha);
    RUN_TEST(test_load_json_sem_colchete_de_abertura_falha);

    RUN_TEST(test_upsert_insere_novo);
    RUN_TEST(test_upsert_mesma_chave_substitui_sem_duplicar);
    RUN_TEST(test_upsert_copia_strings_nao_guarda_ponteiros_recebidos);

    RUN_TEST(test_round_trip_save_depois_load);
    RUN_TEST(test_round_trip_preserva_caracteres_especiais_no_produto);
    RUN_TEST(test_save_cria_diretorio_pai_se_nao_existir);

    return UNITY_END();
}
