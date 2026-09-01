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

/* ---------------------------------------------------------------------
 * cve_array_linear_search
 * (mesmos casos essenciais da binaria - a linear nao tem fronteiras
 * low/high/mid pra testar, mas os casos de borda do array ainda valem.)
 * ------------------------------------------------------------------- */

static void test_linear_array_vazio_nunca_encontra(void)
{
    CVEArray array = {0};
    size_t index = 0U;

    TEST_ASSERT_FALSE(cve_array_linear_search(&array, 2025U, 1U, &index));
}

static void test_linear_encontra_o_primeiro_elemento(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_TRUE(cve_array_linear_search(&array, 2025U, 1U, &index));
    TEST_ASSERT_EQUAL_size_t(0U, index);
}

static void test_linear_encontra_o_ultimo_elemento(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_TRUE(cve_array_linear_search(&array, 2026U, 100U, &index));
    TEST_ASSERT_EQUAL_size_t(4U, index);
}

static void test_linear_nao_encontra_chave_em_um_buraco(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_FALSE(cve_array_linear_search(&array, 2025U, 3U, &index));
}

static void test_linear_argumentos_nulos_retornam_zero(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_FALSE(cve_array_linear_search(NULL, 2025U, 1U, &index));
    TEST_ASSERT_FALSE(cve_array_linear_search(&array, 2025U, 1U, NULL));
}

static void test_linear_varredura_encontra_cada_elemento_no_indice_certo(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t i;

    for (i = 0U; i < array.count; ++i) {
        size_t index = (size_t)-1;
        int found = cve_array_linear_search(
            &array, array.items[i].year, array.items[i].number, &index
        );

        TEST_ASSERT_TRUE(found);
        TEST_ASSERT_EQUAL_size_t(i, index);
    }
}

/* ---------------------------------------------------------------------
 * Validacao cruzada: binaria e linear tem que sempre concordar, tanto em
 * "achou/nao achou" quanto no indice. A linear e' a referencia "burra e
 * confiavel" - se as duas divergem, o bug esta' na binaria.
 * ------------------------------------------------------------------- */

static void test_binaria_e_linear_concordam_em_todo_o_array_fixo(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    uint32_t year;

    /* Chaves plausiveis de 2020 a 2027, numero de 1 a 105: cobre todo
     * acerto do array fixo e varios "buracos" ao redor deles. */
    for (year = 2020U; year <= 2027U; ++year) {
        uint32_t number;

        for (number = 1U; number <= 105U; ++number) {
            size_t index_binaria = (size_t)-1;
            size_t index_linear = (size_t)-1;
            int found_binaria = cve_array_binary_search(&array, year, number, &index_binaria);
            int found_linear = cve_array_linear_search(&array, year, number, &index_linear);

            TEST_ASSERT_EQUAL_INT(found_linear, found_binaria);
            if (found_linear) {
                TEST_ASSERT_EQUAL_size_t(index_linear, index_binaria);
            }
        }
    }
}

/* ---------------------------------------------------------------------
 * variantes _counted
 * ------------------------------------------------------------------- */

static void test_counted_out_comparisons_nulo_nao_quebra(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;

    TEST_ASSERT_TRUE(cve_array_binary_search_counted(&array, 2025U, 1U, &index, NULL));
    TEST_ASSERT_TRUE(cve_array_linear_search_counted(&array, 2025U, 1U, &index, NULL));
}

static void test_counted_binaria_conta_no_maximo_log2_mais_um_comparacoes(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;
    size_t comparisons = 0U;

    /* Pior caso (nao encontrado) em 5 elementos: no maximo
     * ceil(log2(5)) + 1 = 4 comparacoes. */
    TEST_ASSERT_FALSE(cve_array_binary_search_counted(&array, 2025U, 3U, &index, &comparisons));
    TEST_ASSERT_TRUE(comparisons >= 1U);
    TEST_ASSERT_TRUE(comparisons <= 4U);
}

static void test_counted_linear_pior_caso_conta_exatamente_count_comparacoes(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;
    size_t comparisons = 0U;

    /* Chave que nao existe: a linear tem que olhar todos os 5 elementos. */
    TEST_ASSERT_FALSE(cve_array_linear_search_counted(&array, 2025U, 3U, &index, &comparisons));
    TEST_ASSERT_EQUAL_size_t(array.count, comparisons);
}

static void test_counted_linear_encontra_primeiro_em_uma_comparacao(void)
{
    CVE storage[5];
    CVEArray array = make_fixed_array(storage);
    size_t index = 0U;
    size_t comparisons = 0U;

    TEST_ASSERT_TRUE(cve_array_linear_search_counted(&array, 2025U, 1U, &index, &comparisons));
    TEST_ASSERT_EQUAL_size_t(1U, comparisons);
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

    RUN_TEST(test_linear_array_vazio_nunca_encontra);
    RUN_TEST(test_linear_encontra_o_primeiro_elemento);
    RUN_TEST(test_linear_encontra_o_ultimo_elemento);
    RUN_TEST(test_linear_nao_encontra_chave_em_um_buraco);
    RUN_TEST(test_linear_argumentos_nulos_retornam_zero);
    RUN_TEST(test_linear_varredura_encontra_cada_elemento_no_indice_certo);

    RUN_TEST(test_binaria_e_linear_concordam_em_todo_o_array_fixo);

    RUN_TEST(test_counted_out_comparisons_nulo_nao_quebra);
    RUN_TEST(test_counted_binaria_conta_no_maximo_log2_mais_um_comparacoes);
    RUN_TEST(test_counted_linear_pior_caso_conta_exatamente_count_comparacoes);
    RUN_TEST(test_counted_linear_encontra_primeiro_em_uma_comparacao);

    return UNITY_END();
}
