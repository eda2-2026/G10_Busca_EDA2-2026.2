#include "unity.h"
#include "product.h"

#include <stdio.h>

void setUp(void) {}

#define FIXTURE_PATH "build/tests/fixture_product.csv"

void tearDown(void)
{
    remove(FIXTURE_PATH);
}

static Product make_product(uint32_t year, uint32_t number, char *cve_id, char *name)
{
    Product product = {0};
    product.year = year;
    product.number = number;
    product.cve_id = cve_id;
    product.product = name;
    return product;
}

/* ---------------------------------------------------------------------
 * product_compare_key / product_array_is_sorted_by_key
 * ------------------------------------------------------------------- */

static void test_compare_key_ano_menor_vem_antes(void)
{
    Product a = make_product(2024, 1, NULL, NULL);
    Product b = make_product(2025, 1, NULL, NULL);

    TEST_ASSERT_TRUE(product_compare_key(&a, &b) < 0);
    TEST_ASSERT_TRUE(product_compare_key(&b, &a) > 0);
}

static void test_compare_key_mesmo_cve_produtos_diferentes_sao_iguais_na_chave(void)
{
    Product a = make_product(2025, 3, NULL, "A");
    Product b = make_product(2025, 3, NULL, "B");

    /* A chave e' (year, number): dois produtos do mesmo CVE tem chave
     * igual, mesmo com nomes de produto diferentes. */
    TEST_ASSERT_EQUAL_INT(0, product_compare_key(&a, &b));
}

static void test_array_vazio_e_considerado_ordenado(void)
{
    ProductArray array = {0};

    TEST_ASSERT_TRUE(product_array_is_sorted_by_key(&array));
}

static void test_array_fora_de_ordem_e_detectado(void)
{
    Product items[2] = {
        make_product(2025, 5, NULL, "X"),
        make_product(2025, 1, NULL, "Y"),
    };
    ProductArray array = { .items = items, .count = 2, .capacity = 2 };

    TEST_ASSERT_FALSE(product_array_is_sorted_by_key(&array));
}

/* ---------------------------------------------------------------------
 * product_array_load_csv
 * ------------------------------------------------------------------- */

static void write_fixture(const char *content)
{
    FILE *file = fopen(FIXTURE_PATH, "wb");

    TEST_ASSERT_NOT_NULL(file);
    fputs(content, file);
    fclose(file);
}

static void test_load_csv_arquivo_valido_com_aspas_e_escapes(void)
{
    ProductArray array = {0};

    write_fixture(
        "cve_id,product\n"
        "CVE-2025-0001,OpenSSL\n"
        "CVE-2025-0002,\"Product A, Model X\"\n"
        "CVE-2025-0002,Product\\nB\n"
        "CVE-2025-0003,Widget\n"
    );

    TEST_ASSERT_TRUE(product_array_load_csv(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(4U, array.count);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", array.items[0].cve_id);
    TEST_ASSERT_EQUAL_UINT32(2025U, array.items[0].year);
    TEST_ASSERT_EQUAL_UINT32(1U, array.items[0].number);
    TEST_ASSERT_EQUAL_STRING("OpenSSL", array.items[0].product);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0002", array.items[1].cve_id);
    TEST_ASSERT_EQUAL_STRING("Product A, Model X", array.items[1].product);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0002", array.items[2].cve_id);
    TEST_ASSERT_EQUAL_STRING("Product\nB", array.items[2].product);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0003", array.items[3].cve_id);
    TEST_ASSERT_EQUAL_STRING("Widget", array.items[3].product);

    product_array_free(&array);
}

static void test_load_csv_cabecalho_ausente_arquivo_vazio(void)
{
    ProductArray array = {0};

    write_fixture("");

    TEST_ASSERT_FALSE(product_array_load_csv(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);
    TEST_ASSERT_NULL(array.items);
}

static void test_load_csv_cabecalho_com_coluna_errada(void)
{
    ProductArray array = {0};

    write_fixture("cve_id,vendor\n");

    TEST_ASSERT_FALSE(product_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_linha_com_numero_de_colunas_errado(void)
{
    ProductArray array = {0};

    write_fixture(
        "cve_id,product\n"
        "CVE-2025-0001,OpenSSL,extra\n"
    );

    TEST_ASSERT_FALSE(product_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_cve_id_invalido(void)
{
    ProductArray array = {0};

    write_fixture(
        "cve_id,product\n"
        "nao-e-um-cve,OpenSSL\n"
    );

    TEST_ASSERT_FALSE(product_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_produto_vazio_e_invalido(void)
{
    ProductArray array = {0};

    write_fixture(
        "cve_id,product\n"
        "CVE-2025-0001,\n"
    );

    TEST_ASSERT_FALSE(product_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_arquivo_inexistente(void)
{
    ProductArray array = {0};

    TEST_ASSERT_FALSE(product_array_load_csv(&array, "build/tests/nao_existe.csv"));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);
}

/* ---------------------------------------------------------------------
 * product_array_lower_bound / product_array_find_for_cve
 *
 * Array fixo usado nos testes abaixo (indices entre colchetes):
 * [0] CVE-2025-0001 (1 produto)
 * [1..3] CVE-2025-0003 (3 produtos)
 * [4] CVE-2025-0007 (1 produto)
 * [5] CVE-2026-0001 (1 produto)
 * CVE-2025-0002, 0004, 0005 e 0006 nao tem produtos (nao aparecem).
 * ------------------------------------------------------------------- */

static ProductArray make_fixed_array(Product *storage)
{
    storage[0] = make_product(2025, 1, "CVE-2025-0001", "A");
    storage[1] = make_product(2025, 3, "CVE-2025-0003", "B1");
    storage[2] = make_product(2025, 3, "CVE-2025-0003", "B2");
    storage[3] = make_product(2025, 3, "CVE-2025-0003", "B3");
    storage[4] = make_product(2025, 7, "CVE-2025-0007", "C");
    storage[5] = make_product(2026, 1, "CVE-2026-0001", "D");

    return (ProductArray){ .items = storage, .count = 6, .capacity = 6 };
}

static void test_lower_bound_array_vazio(void)
{
    ProductArray array = {0};

    TEST_ASSERT_EQUAL_size_t(0U, product_array_lower_bound(&array, 2025U, 1U));
}

static void test_lower_bound_chave_menor_que_tudo(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);

    TEST_ASSERT_EQUAL_size_t(0U, product_array_lower_bound(&array, 2020U, 1U));
}

static void test_lower_bound_chave_maior_que_tudo(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);

    TEST_ASSERT_EQUAL_size_t(6U, product_array_lower_bound(&array, 2027U, 1U));
}

static void test_lower_bound_chave_exata_no_inicio_de_um_grupo(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);

    TEST_ASSERT_EQUAL_size_t(1U, product_array_lower_bound(&array, 2025U, 3U));
}

static void test_lower_bound_chave_em_um_buraco(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);

    /* CVE-2025-0002 nao existe: cai entre os indices 0 e 1. */
    TEST_ASSERT_EQUAL_size_t(1U, product_array_lower_bound(&array, 2025U, 2U));
    /* CVE-2025-0004 nao existe: cai entre os indices 3 e 4. */
    TEST_ASSERT_EQUAL_size_t(4U, product_array_lower_bound(&array, 2025U, 4U));
}

static void test_find_for_cve_com_um_produto(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);
    size_t start = 0U;
    size_t count = 0U;

    product_array_find_for_cve(&array, 2025U, 1U, &start, &count);
    TEST_ASSERT_EQUAL_size_t(0U, start);
    TEST_ASSERT_EQUAL_size_t(1U, count);
}

static void test_find_for_cve_com_varios_produtos(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);
    size_t start = 0U;
    size_t count = 0U;

    product_array_find_for_cve(&array, 2025U, 3U, &start, &count);
    TEST_ASSERT_EQUAL_size_t(1U, start);
    TEST_ASSERT_EQUAL_size_t(3U, count);
    TEST_ASSERT_EQUAL_STRING("B1", array.items[start].product);
    TEST_ASSERT_EQUAL_STRING("B3", array.items[start + count - 1U].product);
}

static void test_find_for_cve_ultimo_elemento_do_array(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);
    size_t start = 0U;
    size_t count = 0U;

    product_array_find_for_cve(&array, 2026U, 1U, &start, &count);
    TEST_ASSERT_EQUAL_size_t(5U, start);
    TEST_ASSERT_EQUAL_size_t(1U, count);
}

static void test_find_for_cve_sem_produtos_no_meio_do_array(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);
    size_t start = 0U;
    size_t count = 0U;

    product_array_find_for_cve(&array, 2025U, 2U, &start, &count);
    TEST_ASSERT_EQUAL_size_t(0U, count);
}

static void test_find_for_cve_sem_produtos_apos_o_fim_do_array(void)
{
    Product storage[6];
    ProductArray array = make_fixed_array(storage);
    size_t start = 0U;
    size_t count = 0U;

    product_array_find_for_cve(&array, 2027U, 1U, &start, &count);
    TEST_ASSERT_EQUAL_size_t(6U, start);
    TEST_ASSERT_EQUAL_size_t(0U, count);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_compare_key_ano_menor_vem_antes);
    RUN_TEST(test_compare_key_mesmo_cve_produtos_diferentes_sao_iguais_na_chave);
    RUN_TEST(test_array_vazio_e_considerado_ordenado);
    RUN_TEST(test_array_fora_de_ordem_e_detectado);

    RUN_TEST(test_load_csv_arquivo_valido_com_aspas_e_escapes);
    RUN_TEST(test_load_csv_cabecalho_ausente_arquivo_vazio);
    RUN_TEST(test_load_csv_cabecalho_com_coluna_errada);
    RUN_TEST(test_load_csv_linha_com_numero_de_colunas_errado);
    RUN_TEST(test_load_csv_cve_id_invalido);
    RUN_TEST(test_load_csv_produto_vazio_e_invalido);
    RUN_TEST(test_load_csv_arquivo_inexistente);

    RUN_TEST(test_lower_bound_array_vazio);
    RUN_TEST(test_lower_bound_chave_menor_que_tudo);
    RUN_TEST(test_lower_bound_chave_maior_que_tudo);
    RUN_TEST(test_lower_bound_chave_exata_no_inicio_de_um_grupo);
    RUN_TEST(test_lower_bound_chave_em_um_buraco);

    RUN_TEST(test_find_for_cve_com_um_produto);
    RUN_TEST(test_find_for_cve_com_varios_produtos);
    RUN_TEST(test_find_for_cve_ultimo_elemento_do_array);
    RUN_TEST(test_find_for_cve_sem_produtos_no_meio_do_array);
    RUN_TEST(test_find_for_cve_sem_produtos_apos_o_fim_do_array);

    return UNITY_END();
}
