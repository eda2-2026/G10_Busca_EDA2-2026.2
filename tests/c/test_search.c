#include "unity.h"
#include "search.h"

void setUp(void) {}
void tearDown(void) {}

static CVE make_cve(uint32_t year, uint32_t number)
{
    CVE cve = {0};
    cve.year = year;
    cve.number = number;
    return cve;
}

/* Array fixo usado na maioria dos testes (indices entre colchetes):
 * [0] 2025-0001  [1] 2025-0005  [2] 2025-0009  [3] 2026-0001  [4] 2026-0100
 */
static CVEArray make_fixed_array(CVE *storage)
{
    storage[0] = make_cve(2025, 1);
    storage[1] = make_cve(2025, 5);
    storage[2] = make_cve(2025, 9);
    storage[3] = make_cve(2026, 1);
    storage[4] = make_cve(2026, 100);

    return (CVEArray){ .items = storage, .count = 5, .capacity = 5 };
}

/* ---------------------------------------------------------------------
 * cve_array_binary_search
 * ------------------------------------------------------------------- */

static void test_array_vazio_nunca_encontra(void)
{
    CVEArray array = {0};
    size_t index = 999U;

    TEST_ASSERT_FALSE(cve_array_binary_search(&array, 2025U, 1U, &index));
    TEST_ASSERT_EQUAL_size_t(999U, index); /* nao deve ter sido escrito */
}

static void test_array_de_um_elemento_encontra(void)
{
    CVE storage[1] = { make_cve(2025, 42) };
    CVEArray array = { .items = storage, .count = 1, .capacity = 1 };
    size_t index = 0U;

    TEST_ASSERT_TRUE(cve_array_binary_search(&array, 2025U, 42U, &index));
    TEST_ASSERT_EQUAL_size_t(0U, index);
}

static void test_array_de_um_elemento_nao_encontra_outra_chave(void)
{
    CVE storage[1] = { make_cve(2025, 42) };
    CVEArray array = { .items = storage, .count = 1, .capacity = 1 };
    size_t index = 0U;

    TEST_ASSERT_FALSE(cve_array_binary_search(&array, 2025U, 43U, &index));
}

static void test_encontra_o_primeiro_elemento(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_TRUE(cve_array_binary_search(&array, 2025U, 1U, &index));
    TEST_ASSERT_EQUAL_size_t(0U, index);
}

static void test_encontra_o_ultimo_elemento(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_TRUE(cve_array_binary_search(&array, 2026U, 100U, &index));
    TEST_ASSERT_EQUAL_size_t(4U, index);
}

static void test_encontra_elemento_do_meio(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_TRUE(cve_array_binary_search(&array, 2025U, 9U, &index));
    TEST_ASSERT_EQUAL_size_t(2U, index);
}

static void test_nao_encontra_chave_antes_do_primeiro(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_FALSE(cve_array_binary_search(&array, 2020U, 1U, &index));
}

static void test_nao_encontra_chave_depois_do_ultimo(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_FALSE(cve_array_binary_search(&array, 2030U, 1U, &index));
}

static void test_nao_encontra_chave_em_um_buraco_mesmo_ano(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    /* 2025-0003 fica entre 2025-0001 e 2025-0005, mas nao existe. */
    TEST_ASSERT_FALSE(cve_array_binary_search(&array, 2025U, 3U, &index));
}

static void test_nao_encontra_chave_em_um_buraco_entre_anos(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    /* Nenhum elemento de 2025 depois do 0009 nem antes do 2026-0001. */
    TEST_ASSERT_FALSE(cve_array_binary_search(&array, 2025U, 50U, &index));
}

static void test_argumentos_nulos_retornam_zero(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_FALSE(cve_array_binary_search(NULL, 2025U, 1U, &index));
    TEST_ASSERT_FALSE(cve_array_binary_search(&array, 2025U, 1U, NULL));
}

static void test_varredura_encontra_cada_elemento_no_indice_certo(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t i;

    /* Varre todo o array: cada elemento deve ser encontrado exatamente no
     * seu proprio indice. Pega sistematicamente erros de "off-by-one" nas
     * fronteiras low/high/mid que um unico caso isolado poderia esconder. */
    for (i = 0U; i < array.count; ++i) {
        size_t index = (size_t)-1;
        int found = cve_array_binary_search(
            &array, array.items[i].year, array.items[i].number, &index
        );

        TEST_ASSERT_TRUE(found);
        TEST_ASSERT_EQUAL_size_t(i, index);
    }
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_array_vazio_nunca_encontra);
    RUN_TEST(test_array_de_um_elemento_encontra);
    RUN_TEST(test_array_de_um_elemento_nao_encontra_outra_chave);
    RUN_TEST(test_encontra_o_primeiro_elemento);
    RUN_TEST(test_encontra_o_ultimo_elemento);
    RUN_TEST(test_encontra_elemento_do_meio);
    RUN_TEST(test_nao_encontra_chave_antes_do_primeiro);
    RUN_TEST(test_nao_encontra_chave_depois_do_ultimo);
    RUN_TEST(test_nao_encontra_chave_em_um_buraco_mesmo_ano);
    RUN_TEST(test_nao_encontra_chave_em_um_buraco_entre_anos);
    RUN_TEST(test_argumentos_nulos_retornam_zero);
    RUN_TEST(test_varredura_encontra_cada_elemento_no_indice_certo);

    return UNITY_END();
}
