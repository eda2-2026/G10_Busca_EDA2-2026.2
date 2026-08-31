#include "unity.h"
#include "product_index.h"

#include <stddef.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static Product make_product(
    char *cve_id,
    uint32_t year,
    uint32_t number,
    char *name
)
{
    Product product = {0};

    product.cve_id = cve_id;
    product.year = year;
    product.number = number;
    product.product = name;
    return product;
}

static ProductArray make_search_fixture(Product *storage)
{
    storage[0] = make_product("CVE-2025-0005", 2025U, 5U, "Zulu");
    storage[1] = make_product("CVE-2025-0003", 2025U, 3U, "WordPress");
    storage[2] = make_product("CVE-2025-0001", 2025U, 1U, "Alpha");
    storage[3] = make_product("CVE-2025-0004", 2025U, 4U, "wordpress");
    storage[4] = make_product("CVE-2025-0002", 2025U, 2U, "Beta");

    return (ProductArray){ .items = storage, .count = 5U, .capacity = 5U };
}

static void assert_result_cve(
    const ProductNameIndex *index,
    size_t result_position,
    const char *expected_cve_id
)
{
    const Product *product = product_name_index_get(index, result_position);

    TEST_ASSERT_NOT_NULL(product);
    TEST_ASSERT_EQUAL_STRING(expected_cve_id, product->cve_id);
}

static void assert_range_contains_cve(
    const ProductNameIndex *index,
    size_t start,
    size_t count,
    const char *expected_cve_id
)
{
    size_t offset;

    for (offset = 0U; offset < count; ++offset) {
        const Product *product = product_name_index_get(index, start + offset);

        if (product != NULL && strcmp(product->cve_id, expected_cve_id) == 0) {
            return;
        }
    }

    TEST_FAIL_MESSAGE("CVE esperada nao encontrada no intervalo");
}

static void test_compare_ascii_ignora_maiusculas_e_minusculas(void)
{
    TEST_ASSERT_EQUAL_INT(0, product_name_compare_ascii("WordPress", "wordpress"));
    TEST_ASSERT_EQUAL_INT(0, product_name_compare_ascii("WORDPRESS", "wordpress"));
}

static void test_compare_ascii_preserva_ordem_lexicografica(void)
{
    TEST_ASSERT_LESS_THAN_INT(0, product_name_compare_ascii("Alpha", "beta"));
    TEST_ASSERT_GREATER_THAN_INT(0, product_name_compare_ascii("Zulu", "beta"));
}

static void test_compare_ascii_define_ordem_para_argumentos_nulos(void)
{
    TEST_ASSERT_EQUAL_INT(0, product_name_compare_ascii(NULL, NULL));
    TEST_ASSERT_LESS_THAN_INT(0, product_name_compare_ascii(NULL, "Widget"));
    TEST_ASSERT_GREATER_THAN_INT(0, product_name_compare_ascii("Widget", NULL));
}

static void test_build_array_vazio(void)
{
    ProductArray products = {0};
    ProductNameIndex index = {0};

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_NULL(index.items);
    TEST_ASSERT_EQUAL_size_t(0U, index.count);
    TEST_ASSERT_EQUAL_PTR(&products, index.source);

    product_name_index_free(&index);
}

static void test_build_um_elemento(void)
{
    Product storage[1] = {
        make_product("CVE-2025-0001", 2025U, 1U, "Widget")
    };
    ProductArray products = { .items = storage, .count = 1U, .capacity = 1U };
    ProductNameIndex index = {0};

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_EQUAL_size_t(1U, index.count);
    TEST_ASSERT_EQUAL_STRING("Widget", index.items[0].product_name);
    TEST_ASSERT_EQUAL_size_t(0U, index.items[0].product_index);

    product_name_index_free(&index);
}

static void test_build_multiplos_preserva_product_array(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    Product *original_items = products.items;
    char *original_first_name = products.items[0].product;
    ProductNameIndex index = {0};

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_EQUAL_size_t(5U, index.count);
    TEST_ASSERT_EQUAL_PTR(original_items, products.items);
    TEST_ASSERT_EQUAL_size_t(5U, products.count);
    TEST_ASSERT_EQUAL_STRING(original_first_name, products.items[0].product);
    TEST_ASSERT_EQUAL_STRING("WordPress", products.items[1].product);

    product_name_index_free(&index);
}

static void test_build_deixa_indice_ordenado(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t position;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    for (position = 1U; position < index.count; ++position) {
        TEST_ASSERT_LESS_OR_EQUAL_INT(
            0,
            product_name_compare_ascii(
                index.items[position - 1U].product_name,
                index.items[position].product_name
            )
        );
    }
    TEST_ASSERT_EQUAL_STRING("Alpha", index.items[0].product_name);
    TEST_ASSERT_EQUAL_STRING("Zulu", index.items[index.count - 1U].product_name);

    product_name_index_free(&index);
}

static void test_build_rejeita_argumentos_invalidos(void)
{
    Product valid_storage[1] = {
        make_product("CVE-2025-0001", 2025U, 1U, "Widget")
    };
    Product invalid_storage[1] = {
        make_product("CVE-2025-0001", 2025U, 1U, NULL)
    };
    Product empty_name_storage[1] = {
        make_product("CVE-2025-0001", 2025U, 1U, "")
    };
    ProductArray valid = { .items = valid_storage, .count = 1U, .capacity = 1U };
    ProductArray inconsistent = { .items = NULL, .count = 1U, .capacity = 1U };
    ProductArray invalid = { .items = invalid_storage, .count = 1U, .capacity = 1U };
    ProductArray empty_name = {
        .items = empty_name_storage, .count = 1U, .capacity = 1U
    };
    ProductNameIndex index = {0};
    ProductNameIndex already_initialized = { .source = &valid };

    TEST_ASSERT_FALSE(product_name_index_build(NULL, &valid));
    TEST_ASSERT_FALSE(product_name_index_build(&index, NULL));
    TEST_ASSERT_FALSE(product_name_index_build(&index, &inconsistent));
    TEST_ASSERT_FALSE(product_name_index_build(&index, &invalid));
    TEST_ASSERT_FALSE(product_name_index_build(&index, &empty_name));
    TEST_ASSERT_FALSE(product_name_index_build(&already_initialized, &valid));
    TEST_ASSERT_NULL(index.items);
    TEST_ASSERT_EQUAL_size_t(0U, index.count);
    TEST_ASSERT_NULL(index.source);
}

static void test_free_zera_estrutura(void)
{
    Product storage[1] = {
        make_product("CVE-2025-0001", 2025U, 1U, "Widget")
    };
    ProductArray products = { .items = storage, .count = 1U, .capacity = 1U };
    ProductNameIndex index = {0};

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    product_name_index_free(&index);

    TEST_ASSERT_NULL(index.items);
    TEST_ASSERT_EQUAL_size_t(0U, index.count);
    TEST_ASSERT_NULL(index.source);
    TEST_ASSERT_EQUAL_size_t(1U, products.count);
    TEST_ASSERT_EQUAL_PTR(storage, products.items);
    TEST_ASSERT_EQUAL_STRING("Widget", products.items[0].product);
    product_name_index_free(&index);
    TEST_ASSERT_EQUAL_size_t(1U, products.count);
    TEST_ASSERT_EQUAL_STRING("Widget", products.items[0].product);
    product_name_index_free(NULL);
}

static void test_busca_produto_associado_a_uma_cve(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "Beta", &start, &count));
    TEST_ASSERT_EQUAL_size_t(1U, count);
    assert_result_cve(&index, start, "CVE-2025-0002");

    product_name_index_free(&index);
}

static void test_busca_produto_associado_a_varias_cves(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "WordPress", &start, &count));
    TEST_ASSERT_EQUAL_size_t(2U, count);
    assert_range_contains_cve(&index, start, count, "CVE-2025-0003");
    assert_range_contains_cve(&index, start, count, "CVE-2025-0004");

    product_name_index_free(&index);
}

static void test_busca_produto_inexistente(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start = 99U;
    size_t count = 99U;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "Delta", &start, &count));
    TEST_ASSERT_EQUAL_size_t(0U, count);

    product_name_index_free(&index);
}

static void test_busca_wordpress_minusculo(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "wordpress", &start, &count));
    TEST_ASSERT_EQUAL_size_t(2U, count);
    product_name_index_free(&index);
}

static void test_busca_wordpress_maiusculo(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "WORDPRESS", &start, &count));
    TEST_ASSERT_EQUAL_size_t(2U, count);
    product_name_index_free(&index);
}

static void test_busca_primeira_chave(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "alpha", &start, &count));
    TEST_ASSERT_EQUAL_size_t(0U, start);
    TEST_ASSERT_EQUAL_size_t(1U, count);
    product_name_index_free(&index);
}

static void test_busca_ultima_chave(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "zulu", &start, &count));
    TEST_ASSERT_EQUAL_size_t(index.count - 1U, start);
    TEST_ASSERT_EQUAL_size_t(1U, count);
    product_name_index_free(&index);
}

static void test_lower_bound_chave_entre_dois_nomes(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t position;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    position = product_name_index_lower_bound(&index, "Delta");
    TEST_ASSERT_TRUE(position < index.count);
    TEST_ASSERT_EQUAL_INT(
        0,
        product_name_compare_ascii(index.items[position].product_name, "WordPress")
    );
    product_name_index_free(&index);
}

static void test_lower_bound_depois_da_ultima_chave(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_EQUAL_size_t(
        index.count,
        product_name_index_lower_bound(&index, "Zzzzz")
    );
    product_name_index_free(&index);
}

static void test_busca_nome_vazio_e_invalida(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start = 99U;
    size_t count = 99U;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_FALSE(product_name_index_find_exact(&index, "", &start, &count));
    TEST_ASSERT_EQUAL_size_t(0U, start);
    TEST_ASSERT_EQUAL_size_t(0U, count);
    product_name_index_free(&index);
}

static void test_busca_indice_vazio(void)
{
    ProductArray products = {0};
    ProductNameIndex index = {0};
    size_t start = 99U;
    size_t count = 99U;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "Widget", &start, &count));
    TEST_ASSERT_EQUAL_size_t(0U, start);
    TEST_ASSERT_EQUAL_size_t(0U, count);
    product_name_index_free(&index);
}

static void test_busca_rejeita_argumentos_nulos(void)
{
    Product storage[5];
    ProductArray products = make_search_fixture(storage);
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_FALSE(product_name_index_find_exact(NULL, "Widget", &start, &count));
    TEST_ASSERT_FALSE(product_name_index_find_exact(&index, NULL, &start, &count));
    TEST_ASSERT_FALSE(product_name_index_find_exact(&index, "Widget", NULL, &count));
    TEST_ASSERT_FALSE(product_name_index_find_exact(&index, "Widget", &start, NULL));
    TEST_ASSERT_EQUAL_size_t(0U, product_name_index_lower_bound(NULL, "Widget"));
    TEST_ASSERT_EQUAL_size_t(0U, product_name_index_lower_bound(&index, NULL));
    product_name_index_free(&index);
}

static void test_busca_nome_longo(void)
{
    char long_name[1804];
    Product storage[1];
    ProductArray products;
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    memset(long_name, 'x', sizeof(long_name) - 1U);
    long_name[sizeof(long_name) - 1U] = '\0';
    storage[0] = make_product("CVE-2025-0001", 2025U, 1U, long_name);
    products = (ProductArray){ .items = storage, .count = 1U, .capacity = 1U };

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, long_name, &start, &count));
    TEST_ASSERT_EQUAL_size_t(1U, count);
    assert_result_cve(&index, start, "CVE-2025-0001");
    product_name_index_free(&index);
}

static void test_busca_utf8_aplica_case_insensitive_somente_ao_ascii(void)
{
    Product storage[1] = {
        make_product("CVE-2025-0001", 2025U, 1U, "Caf\xC3\xA9")
    };
    ProductArray products = { .items = storage, .count = 1U, .capacity = 1U };
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "caf\xC3\xA9", &start, &count));
    TEST_ASSERT_EQUAL_size_t(1U, count);
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "CAF\xC3\x89", &start, &count));
    TEST_ASSERT_EQUAL_size_t(0U, count);
    product_name_index_free(&index);
}

static void test_relacoes_duplicadas_permanecem_no_indice(void)
{
    Product storage[3] = {
        make_product("CVE-2025-0001", 2025U, 1U, "Widget"),
        make_product("CVE-2025-0001", 2025U, 1U, "widget"),
        make_product("CVE-2025-0001", 2025U, 1U, "WIDGET")
    };
    ProductArray products = { .items = storage, .count = 3U, .capacity = 3U };
    ProductNameIndex index = {0};
    size_t start;
    size_t count;
    int seen[3] = {0, 0, 0};
    size_t offset;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_EQUAL_size_t(products.count, index.count);
    TEST_ASSERT_EQUAL_size_t(3U, index.count);
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "widget", &start, &count));
    TEST_ASSERT_EQUAL_size_t(3U, count);

    for (offset = 0U; offset < count; ++offset) {
        const Product *product = product_name_index_get(&index, start + offset);

        TEST_ASSERT_NOT_NULL(product);
        if (product == &storage[0]) {
            seen[0] = 1;
        } else if (product == &storage[1]) {
            seen[1] = 1;
        } else if (product == &storage[2]) {
            seen[2] = 1;
        } else {
            TEST_FAIL_MESSAGE("Indice retornou Product fora da fonte");
        }
    }

    TEST_ASSERT_TRUE(seen[0]);
    TEST_ASSERT_TRUE(seen[1]);
    TEST_ASSERT_TRUE(seen[2]);
    TEST_ASSERT_EQUAL_size_t(3U, products.count);
    product_name_index_free(&index);
}

static void test_mesmo_produto_em_cves_diferentes_retorna_todas(void)
{
    Product storage[3] = {
        make_product("CVE-2025-0003", 2025U, 3U, "Widget"),
        make_product("CVE-2025-0001", 2025U, 1U, "widget"),
        make_product("CVE-2025-0002", 2025U, 2U, "WIDGET")
    };
    ProductArray products = { .items = storage, .count = 3U, .capacity = 3U };
    ProductNameIndex index = {0};
    size_t start;
    size_t count;

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_TRUE(product_name_index_find_exact(&index, "Widget", &start, &count));
    TEST_ASSERT_EQUAL_size_t(3U, count);
    assert_range_contains_cve(&index, start, count, "CVE-2025-0001");
    assert_range_contains_cve(&index, start, count, "CVE-2025-0002");
    assert_range_contains_cve(&index, start, count, "CVE-2025-0003");
    product_name_index_free(&index);
}

static void test_get_rejeita_posicao_invalida(void)
{
    Product storage[1] = {
        make_product("CVE-2025-0001", 2025U, 1U, "Widget")
    };
    ProductArray products = { .items = storage, .count = 1U, .capacity = 1U };
    ProductNameIndex index = {0};

    TEST_ASSERT_TRUE(product_name_index_build(&index, &products));
    TEST_ASSERT_NULL(product_name_index_get(NULL, 0U));
    TEST_ASSERT_NULL(product_name_index_get(&index, 1U));
    product_name_index_free(&index);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_compare_ascii_ignora_maiusculas_e_minusculas);
    RUN_TEST(test_compare_ascii_preserva_ordem_lexicografica);
    RUN_TEST(test_compare_ascii_define_ordem_para_argumentos_nulos);
    RUN_TEST(test_build_array_vazio);
    RUN_TEST(test_build_um_elemento);
    RUN_TEST(test_build_multiplos_preserva_product_array);
    RUN_TEST(test_build_deixa_indice_ordenado);
    RUN_TEST(test_build_rejeita_argumentos_invalidos);
    RUN_TEST(test_free_zera_estrutura);
    RUN_TEST(test_busca_produto_associado_a_uma_cve);
    RUN_TEST(test_busca_produto_associado_a_varias_cves);
    RUN_TEST(test_busca_produto_inexistente);
    RUN_TEST(test_busca_wordpress_minusculo);
    RUN_TEST(test_busca_wordpress_maiusculo);
    RUN_TEST(test_busca_primeira_chave);
    RUN_TEST(test_busca_ultima_chave);
    RUN_TEST(test_lower_bound_chave_entre_dois_nomes);
    RUN_TEST(test_lower_bound_depois_da_ultima_chave);
    RUN_TEST(test_busca_nome_vazio_e_invalida);
    RUN_TEST(test_busca_indice_vazio);
    RUN_TEST(test_busca_rejeita_argumentos_nulos);
    RUN_TEST(test_busca_nome_longo);
    RUN_TEST(test_busca_utf8_aplica_case_insensitive_somente_ao_ascii);
    RUN_TEST(test_relacoes_duplicadas_permanecem_no_indice);
    RUN_TEST(test_mesmo_produto_em_cves_diferentes_retorna_todas);
    RUN_TEST(test_get_rejeita_posicao_invalida);

    return UNITY_END();
}
