#include "unity.h"
#include "cve.h"

#include <stdio.h>

/* A Unity chama setUp()/tearDown() antes/depois de cada teste. */
void setUp(void) {}

/* Os testes de cve_array_load_csv escrevem um CSV temporário nesse
 * caminho fixo (dentro de build/, que já existe quando os testes rodam e
 * é ignorado pelo git). tearDown() remove o arquivo depois de cada teste,
 * então cada teste começa sempre com um arquivo limpo. */
#define FIXTURE_PATH "build/tests/fixture_cve.csv"

void tearDown(void)
{
    remove(FIXTURE_PATH);
}

static CVE make_cve(uint32_t year, uint32_t number)
{
    CVE cve = {0};
    cve.year = year;
    cve.number = number;
    return cve;
}

static void test_cve_compare_key_ano_menor_vem_antes(void)
{
    CVE a = make_cve(2024, 1);
    CVE b = make_cve(2025, 1);

    TEST_ASSERT_TRUE(cve_compare_key(&a, &b) < 0);
    TEST_ASSERT_TRUE(cve_compare_key(&b, &a) > 0);
}

static void test_cve_compare_key_mesmo_ano_desempata_por_numero(void)
{
    CVE a = make_cve(2025, 1);
    CVE b = make_cve(2025, 2);

    TEST_ASSERT_TRUE(cve_compare_key(&a, &b) < 0);
    TEST_ASSERT_TRUE(cve_compare_key(&b, &a) > 0);
}

static void test_cve_compare_key_chaves_iguais(void)
{
    CVE a = make_cve(2025, 42);
    CVE b = make_cve(2025, 42);

    TEST_ASSERT_EQUAL_INT(0, cve_compare_key(&a, &b));
}

static void test_array_vazio_e_considerado_ordenado(void)
{
    CVEArray array = {0};

    TEST_ASSERT_TRUE(cve_array_is_sorted_by_key(&array));
}

static void test_array_em_ordem_crescente_e_valido(void)
{
    CVE items[3] = {
        make_cve(2025, 1),
        make_cve(2025, 5),
        make_cve(2026, 1),
    };
    CVEArray array = { .items = items, .count = 3, .capacity = 3 };

    TEST_ASSERT_TRUE(cve_array_is_sorted_by_key(&array));
}

static void test_array_fora_de_ordem_e_detectado(void)
{
    CVE items[2] = {
        make_cve(2025, 5),
        make_cve(2025, 1),
    };
    CVEArray array = { .items = items, .count = 2, .capacity = 2 };

    TEST_ASSERT_FALSE(cve_array_is_sorted_by_key(&array));
}


 * cve_parse_key

static void test_parse_key_formato_valido(void)
{
    uint32_t year = 0U;
    uint32_t number = 0U;

    TEST_ASSERT_TRUE(cve_parse_key("CVE-2025-0001", &year, &number));
    TEST_ASSERT_EQUAL_UINT32(2025U, year);
    TEST_ASSERT_EQUAL_UINT32(1U, number);
}

static void test_parse_key_numero_com_mais_de_4_digitos(void)
{
    uint32_t year = 0U;
    uint32_t number = 0U;

    TEST_ASSERT_TRUE(cve_parse_key("CVE-2025-123456", &year, &number));
    TEST_ASSERT_EQUAL_UINT32(2025U, year);
    TEST_ASSERT_EQUAL_UINT32(123456U, number);
}

static void test_parse_key_rejeita_prefixo_errado(void)
{
    uint32_t year = 0U;
    uint32_t number = 0U;

    TEST_ASSERT_FALSE(cve_parse_key("XXX-2025-0001", &year, &number));
}

static void test_parse_key_rejeita_zero_a_esquerda_alem_do_minimo(void)
{
    uint32_t year = 0U;
    uint32_t number = 0U;

    /* "00001" tem 5 digitos mas comeca com zero: nao e' a forma canonica. */
    TEST_ASSERT_FALSE(cve_parse_key("CVE-2025-00001", &year, &number));
}


 * cve_array_load_csv


static void write_fixture(const char *content)
{
    FILE *file = fopen(FIXTURE_PATH, "wb");

    TEST_ASSERT_NOT_NULL(file);
    fputs(content, file);
    fclose(file);
}

static void test_load_csv_arquivo_valido_com_aspas_e_escapes(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "CVE-2025-0001,PUBLISHED,linha1\\nlinha2,\"Titulo, com virgula\",\n"
        "CVE-2025-0002,REJECTED,,,motivo da rejeicao\n"
    );

    TEST_ASSERT_TRUE(cve_array_load_csv(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(2U, array.count);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0001", array.items[0].cve_id);
    TEST_ASSERT_EQUAL_UINT32(2025U, array.items[0].year);
    TEST_ASSERT_EQUAL_UINT32(1U, array.items[0].number);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_PUBLISHED, array.items[0].state);
    TEST_ASSERT_EQUAL_STRING("linha1\nlinha2", array.items[0].description_en);
    TEST_ASSERT_EQUAL_STRING("Titulo, com virgula", array.items[0].title);
    TEST_ASSERT_EQUAL_STRING("", array.items[0].rejection_reason_en);

    TEST_ASSERT_EQUAL_STRING("CVE-2025-0002", array.items[1].cve_id);
    TEST_ASSERT_EQUAL_INT(CVE_STATE_REJECTED, array.items[1].state);
    TEST_ASSERT_EQUAL_STRING("", array.items[1].description_en);
    TEST_ASSERT_EQUAL_STRING("", array.items[1].title);
    TEST_ASSERT_EQUAL_STRING("motivo da rejeicao", array.items[1].rejection_reason_en);

    cve_array_free(&array);
}

static void test_load_csv_cabecalho_ausente_arquivo_vazio(void)
{
    CVEArray array = {0};

    write_fixture("");

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);
    TEST_ASSERT_NULL(array.items);
}

static void test_load_csv_cabecalho_com_coluna_errada(void)
{
    CVEArray array = {0};

    write_fixture("cve_id,state,description_en,title,motivo_errado\n");

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);
}

static void test_load_csv_linha_com_numero_de_colunas_errado(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "CVE-2025-0001,PUBLISHED,descricao,titulo\n" /* falta 1 coluna */
    );

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_cve_id_invalido(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "nao-e-um-cve,PUBLISHED,descricao,titulo,\n"
    );

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_state_desconhecido(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "CVE-2025-0001,EM_ANALISE,descricao,titulo,\n"
    );

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_published_sem_description_e_invalido(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "CVE-2025-0001,PUBLISHED,,titulo,\n"
    );

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_published_com_motivo_de_rejeicao_e_invalido(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "CVE-2025-0001,PUBLISHED,descricao,titulo,nao deveria existir\n"
    );

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_rejected_com_description_e_invalido(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "CVE-2025-0001,REJECTED,nao deveria existir,,motivo\n"
    );

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_rejected_sem_motivo_e_invalido(void)
{
    CVEArray array = {0};

    write_fixture(
        "cve_id,state,description_en,title,rejection_reason_en\n"
        "CVE-2025-0001,REJECTED,,,\n"
    );

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, FIXTURE_PATH));
}

static void test_load_csv_arquivo_inexistente(void)
{
    CVEArray array = {0};

    TEST_ASSERT_FALSE(cve_array_load_csv(&array, "build/tests/nao_existe.csv"));
    TEST_ASSERT_EQUAL_size_t(0U, array.count);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_cve_compare_key_ano_menor_vem_antes);
    RUN_TEST(test_cve_compare_key_mesmo_ano_desempata_por_numero);
    RUN_TEST(test_cve_compare_key_chaves_iguais);
    RUN_TEST(test_array_vazio_e_considerado_ordenado);
    RUN_TEST(test_array_em_ordem_crescente_e_valido);
    RUN_TEST(test_array_fora_de_ordem_e_detectado);

    RUN_TEST(test_parse_key_formato_valido);
    RUN_TEST(test_parse_key_numero_com_mais_de_4_digitos);
    RUN_TEST(test_parse_key_rejeita_prefixo_errado);
    RUN_TEST(test_parse_key_rejeita_zero_a_esquerda_alem_do_minimo);

    RUN_TEST(test_load_csv_arquivo_valido_com_aspas_e_escapes);
    RUN_TEST(test_load_csv_cabecalho_ausente_arquivo_vazio);
    RUN_TEST(test_load_csv_cabecalho_com_coluna_errada);
    RUN_TEST(test_load_csv_linha_com_numero_de_colunas_errado);
    RUN_TEST(test_load_csv_cve_id_invalido);
    RUN_TEST(test_load_csv_state_desconhecido);
    RUN_TEST(test_load_csv_published_sem_description_e_invalido);
    RUN_TEST(test_load_csv_published_com_motivo_de_rejeicao_e_invalido);
    RUN_TEST(test_load_csv_rejected_com_description_e_invalido);
    RUN_TEST(test_load_csv_rejected_sem_motivo_e_invalido);
    RUN_TEST(test_load_csv_arquivo_inexistente);

    return UNITY_END();
}
