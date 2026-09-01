
#include "cve.h"
#include "finder.h"
#include "json.h"
#include "product.h"
#include "product_index.h"
#include "search.h"
#include "selection.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define CVE_CSV_PATH "data/cves.csv"
#define PRODUCT_CSV_PATH "data/products.csv"
#define SELECTIONS_JSON_PATH "output/selections.json"

static void print_error(const char *message)
{
    printf("{\"error\": ");
    json_write_string(stdout, message);
    printf("}\n");
}

static void print_state(CVEState state)
{
    json_write_string(stdout, state == CVE_STATE_PUBLISHED ? "PUBLISHED" : "REJECTED");
}

/* Compara o custo das duas buscas para a MESMA chave/consulta - nao troca
 * o resultado que ja' veio de finder_search/finder_search_product, so'
 * mede quantas comparacoes cada algoritmo teria feito (Fase 5). */
static void print_comparisons(size_t binary, size_t sequential)
{
    printf(", \"comparisons\": {\"binary\": %zu, \"sequential\": %zu}", binary, sequential);
}

/* Registra a CVE encontrada em output/selections.json.*/
static void persist_cve_selection(const FinderResult *result)
{
    SelectionArray selections = {0};
    int upsert_ok;

    if (!selection_array_load_json(&selections, SELECTIONS_JSON_PATH)) {
        return;
    }

    if (result->product_count == 0U) {
        upsert_ok = selection_array_upsert(
            &selections, result->cve->cve_id, result->cve->year, result->cve->state, NULL, 0U
        );
    } else {
        char *product_names[result->product_count];
        size_t index;

        for (index = 0U; index < result->product_count; ++index) {
            product_names[index] = result->products[index].product;
        }
        upsert_ok = selection_array_upsert(
            &selections, result->cve->cve_id, result->cve->year, result->cve->state,
            product_names, result->product_count
        );
    }

    if (upsert_ok) {
        if (!selection_array_save_json(&selections, SELECTIONS_JSON_PATH)) {
            fprintf(stderr, "Aviso: nao foi possivel salvar %s.\n", SELECTIONS_JSON_PATH);
        }
    }
    selection_array_free(&selections);
}

static int run_cve_query(
    const CVEArray *cves,
    const ProductArray *products,
    const char *query
)
{
    FinderResult result = {0};
    size_t dummy_index;
    size_t binary_comparisons = 0U;
    size_t sequential_comparisons = 0U;

    if (!finder_search(cves, products, query, &result)) {
        print_error("Formato invalido. Use CVE-AAAA-NNNN (ex.: CVE-2025-0001).");
        return 1;
    }

    /* finder_search ja' fez a busca "de verdade" (usa a binaria por
     * baixo); rodamos as duas de novo, contadas, so' para mostrar o custo
     * de cada uma lado a lado - o resultado exibido nao muda. */
    cve_array_binary_search_counted(cves, result.year, result.number, &dummy_index, &binary_comparisons);
    cve_array_linear_search_counted(cves, result.year, result.number, &dummy_index, &sequential_comparisons);

    printf("{\"found\": %s", result.found ? "true" : "false");
    if (result.found) {
        size_t index;

        printf(", \"cve_id\": ");
        json_write_string(stdout, result.cve->cve_id);
        printf(", \"year\": %" PRIu32, result.cve->year);
        printf(", \"state\": ");
        print_state(result.cve->state);
        if (result.cve->state == CVE_STATE_PUBLISHED) {
            printf(", \"title\": ");
            json_write_string(stdout, result.cve->title);
            printf(", \"description_en\": ");
            json_write_string(stdout, result.cve->description_en);
        } else {
            printf(", \"rejection_reason_en\": ");
            json_write_string(stdout, result.cve->rejection_reason_en);
        }
        printf(", \"products\": [");
        for (index = 0U; index < result.product_count; ++index) {
            if (index > 0U) {
                printf(", ");
            }
            json_write_string(stdout, result.products[index].product);
        }
        printf("]");
    }
    print_comparisons(binary_comparisons, sequential_comparisons);
    printf("}\n");

    if (result.found) {
        persist_cve_selection(&result);
    }
    return 0;
}

static int run_product_query(
    const CVEArray *cves,
    const ProductArray *products,
    const char *query
)
{
    ProductNameIndex index = {0};
    ProductSearchResult result = {0};
    size_t offset;
    size_t dummy_index;
    size_t binary_comparisons = 0U;
    size_t sequential_comparisons = 0U;

    if (!product_name_index_build(&index, products)) {
        print_error("Nao foi possivel construir o indice de produtos.");
        return 1;
    }

    if (!finder_search_product(&index, query, &result)) {
        print_error("Nome de produto invalido (nao pode ser vazio).");
        product_name_index_free(&index);
        return 1;
    }

    /* Mesma ideia da busca por CVE-ID: a busca "de verdade" ja' rodou
     * acima (indice + binaria); isso so' mede o custo de cada abordagem
     * para a mesma consulta. */
    product_name_index_lower_bound_counted(&index, query, &binary_comparisons);
    product_array_linear_search(products, query, &dummy_index, &sequential_comparisons);

    printf("{\"query\": ");
    json_write_string(stdout, query);
    printf(", \"count\": %zu, \"results\": [", result.count);

    for (offset = 0U; offset < result.count; ++offset) {
        const Product *product = product_name_index_get(result.index, result.start + offset);
        size_t cve_position;

        if (product == NULL) {
            continue;
        }
        if (offset > 0U) {
            printf(", ");
        }

        printf("{\"cve_id\": ");
        json_write_string(stdout, product->cve_id);
        printf(", \"year\": %" PRIu32, product->year);
        printf(", \"product\": ");
        json_write_string(stdout, product->product);

        /* Reaproveita a busca binaria por CVE-ID. */
        if (cve_array_binary_search(cves, product->year, product->number, &cve_position)) {
            printf(", \"state\": ");
            print_state(cves->items[cve_position].state);
        } else {
            printf(", \"state\": null");
        }
        printf("}");
    }

    printf("]");
    print_comparisons(binary_comparisons, sequential_comparisons);
    printf("}\n");
    product_name_index_free(&index);
    return 0;
}

int main(int argc, char **argv)
{
    CVEArray cves = {0};
    ProductArray products = {0};
    int exit_code;

    if (argc != 3 || (strcmp(argv[1], "cve") != 0 && strcmp(argv[1], "product") != 0)) {
        print_error("uso: cve_query <cve|product> <consulta>");
        return 1;
    }

    if (!cve_array_load_csv(&cves, CVE_CSV_PATH)) {
        print_error("Falha ao carregar data/cves.csv no servidor.");
        return 1;
    }
    if (!product_array_load_csv(&products, PRODUCT_CSV_PATH)) {
        print_error("Falha ao carregar data/products.csv no servidor.");
        cve_array_free(&cves);
        return 1;
    }
    if (!cve_array_is_sorted_by_key(&cves) || !product_array_is_sorted_by_key(&products)) {
        print_error("Base carregada fora de ordem no servidor.");
        product_array_free(&products);
        cve_array_free(&cves);
        return 1;
    }

    if (strcmp(argv[1], "cve") == 0) {
        exit_code = run_cve_query(&cves, &products, argv[2]);
    } else {
        exit_code = run_product_query(&cves, &products, argv[2]);
    }

    product_array_free(&products);
    cve_array_free(&cves);
    return exit_code;
}
