#include "unity.h"
#include "finder.h"

void setUp(void) {}
void tearDown(void) {}

static CVE make_cve(uint32_t year, uint32_t number, char *cve_id, CVEState state)
{
    CVE cve = {0};
    cve.year = year;
    cve.number = number;
    cve.cve_id = cve_id;
    cve.state = state;
    return cve;
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

/* Fixture usada na maioria dos testes:
 * CVE-2025-0001 (PUBLISHED, 2 produtos)
 * CVE-2025-0002 (REJECTED, 0 produtos)
 */
static void make_fixture(CVEArray *cves, ProductArray *products, CVE *cve_storage, Product *product_storage)
{
    cve_storage[0] = make_cve(2025, 1, "CVE-2025-0001", CVE_STATE_PUBLISHED);
    cve_storage[1] = make_cve(2025, 2, "CVE-2025-0002", CVE_STATE_REJECTED);
    *cves = (CVEArray){ .items = cve_storage, .count = 2, .capacity = 2 };

    product_storage[0] = make_product(2025, 1, "CVE-2025-0001", "Abacus");
    product_storage[1] = make_product(2025, 1, "CVE-2025-0001", "Widget");
    *products = (ProductArray){ .items = product_storage, .count = 2, .capacity = 2 };
}

static void test_encontra_cve_com_produtos(void)
{
    CVE cve_storage[2];
    Product product_storage[2];
    CVEArray cves;
    ProductArray products;
    FinderResult result = {0};

    make_fixture(&cves, &products, cve_storage, product_storage);

    TEST_ASSERT_TRUE(finder_search(&cves, &products, "CVE-2025-0001", &result));
    TEST_ASSERT_TRUE(result.found);
    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", result.cve->cve_id);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_PUBLISHED, result.cve->state);
    TEST_ASSERT_EQUAL_size_t(2U, result.product_count);
    TEST_ASSERT_EQUAL_STRING("Abacus", result.products[0].product);
    TEST_ASSERT_EQUAL_STRING("Widget", result.products[1].product);
}

static void test_encontra_cve_rejeitado_sem_produtos(void)
{
    CVE cve_storage[2];
    Product product_storage[2];
    CVEArray cves;
    ProductArray products;
    FinderResult result = {0};

    make_fixture(&cves, &products, cve_storage, product_storage);

    TEST_ASSERT_TRUE(finder_search(&cves, &products, "CVE-2025-0002", &result));
    TEST_ASSERT_TRUE(result.found);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_REJECTED, result.cve->state);
    TEST_ASSERT_EQUAL_size_t(0U, result.product_count);
    TEST_ASSERT_NULL(result.products);
}

static void test_aceita_minusculas_e_espacos_nas_pontas(void)
{
    CVE cve_storage[2];
    Product product_storage[2];
    CVEArray cves;
    ProductArray products;
    FinderResult result = {0};

    make_fixture(&cves, &products, cve_storage, product_storage);

    TEST_ASSERT_TRUE(finder_search(&cves, &products, "  cve-2025-0001  ", &result));
    TEST_ASSERT_TRUE(result.found);
    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", result.cve->cve_id);
}

static void test_formato_valido_mas_cve_nao_existe(void)
{
    CVE cve_storage[2];
    Product product_storage[2];
    CVEArray cves;
    ProductArray products;
    FinderResult result = {0};

    make_fixture(&cves, &products, cve_storage, product_storage);

    TEST_ASSERT_TRUE(finder_search(&cves, &products, "CVE-2025-9999", &result));
    TEST_ASSERT_FALSE(result.found);
}

static void test_formato_invalido_retorna_zero(void)
{
    CVE cve_storage[2];
    Product product_storage[2];
    CVEArray cves;
    ProductArray products;
    FinderResult result = {0};

    make_fixture(&cves, &products, cve_storage, product_storage);

    TEST_ASSERT_FALSE(finder_search(&cves, &products, "nao-e-um-cve", &result));
    TEST_ASSERT_FALSE(result.found); /* out_result foi zerado */
}

static void test_entrada_vazia_e_invalida(void)
{
    CVE cve_storage[2];
    Product product_storage[2];
    CVEArray cves;
    ProductArray products;
    FinderResult result = {0};

    make_fixture(&cves, &products, cve_storage, product_storage);

    TEST_ASSERT_FALSE(finder_search(&cves, &products, "   ", &result));
}

static void test_argumentos_nulos_retornam_zero(void)
{
    CVE cve_storage[2];
    Product product_storage[2];
    CVEArray cves;
    ProductArray products;
    FinderResult result = {0};

    make_fixture(&cves, &products, cve_storage, product_storage);

    TEST_ASSERT_FALSE(finder_search(NULL, &products, "CVE-2025-0001", &result));
    TEST_ASSERT_FALSE(finder_search(&cves, NULL, "CVE-2025-0001", &result));
    TEST_ASSERT_FALSE(finder_search(&cves, &products, NULL, &result));
    TEST_ASSERT_FALSE(finder_search(&cves, &products, "CVE-2025-0001", NULL));
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_encontra_cve_com_produtos);
    RUN_TEST(test_encontra_cve_rejeitado_sem_produtos);
    RUN_TEST(test_aceita_minusculas_e_espacos_nas_pontas);
    RUN_TEST(test_formato_valido_mas_cve_nao_existe);
    RUN_TEST(test_formato_invalido_retorna_zero);
    RUN_TEST(test_entrada_vazia_e_invalida);
    RUN_TEST(test_argumentos_nulos_retornam_zero);

    return UNITY_END();
}
