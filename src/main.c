#include "cve.h"
#include "csv.h"
#include "finder.h"
#include "product.h"
#include "selection.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CVE_CSV_PATH "data/cves.csv"
#define PRODUCT_CSV_PATH "data/products.csv"
#define SELECTIONS_JSON_PATH "output/selections.json"

/* Remove espacos nas pontas de `text` em memoria (escreve um '\0' antes
 * dos espacos finais) e retorna o inicio do trecho sem espacos. */
static char *trim_in_place(char *text)
{
    char *start = text;
    char *end;

    while (*start != '\0' && isspace((unsigned char)*start)) {
        ++start;
    }

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) {
        --end;
    }
    *end = '\0';

    return start;
}

static int equals_ignoring_case(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (toupper((unsigned char)*a) != toupper((unsigned char)*b)) {
            return 0;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static void print_result(const char *query, const FinderResult *result)
{
    if (!result->found) {
        printf("%s: nao encontrado.\n\n", query);
        return;
    }

    printf("CVE-ID: %s\n", result->cve->cve_id);
    printf("Ano: %" PRIu32 "\n", result->cve->year);
    printf(
        "Situacao: %s\n",
        result->cve->state == CVE_STATE_PUBLISHED
            ? "aprovada (PUBLISHED)"
            : "rejeitada (REJECTED)"
    );

    if (result->product_count == 0U) {
        printf("Produtos afetados: nenhum\n");
    } else {
        size_t index;

        printf("Produtos afetados (%zu):\n", result->product_count);
        for (index = 0U; index < result->product_count; ++index) {
            printf("  - %s\n", result->products[index].product);
        }
    }
    printf("\n");
}

/* Registra o CVE encontrado em `selections` e regrava output/selections.json
 * (toda busca com sucesso vira uma selecao persistida - Fase 4). */
static void persist_selection(SelectionArray *selections, const FinderResult *result)
{
    int upsert_ok;

    if (result->product_count == 0U) {
        upsert_ok = selection_array_upsert(
            selections, result->cve->cve_id, result->cve->year, result->cve->state, NULL, 0U
        );
    } else {
        char *product_names[result->product_count];
        size_t index;

        for (index = 0U; index < result->product_count; ++index) {
            product_names[index] = result->products[index].product;
        }
        upsert_ok = selection_array_upsert(
            selections, result->cve->cve_id, result->cve->year, result->cve->state,
            product_names, result->product_count
        );
    }

    if (!upsert_ok) {
        fprintf(stderr, "Aviso: falha ao registrar selecao em memoria.\n");
        return;
    }
    if (!selection_array_save_json(selections, SELECTIONS_JSON_PATH)) {
        fprintf(stderr, "Aviso: nao foi possivel salvar %s.\n", SELECTIONS_JSON_PATH);
    }
}

int main(void)
{
    CVEArray cves = {0};
    ProductArray products = {0};
    SelectionArray selections = {0};
    char *line = NULL;
    size_t line_capacity = 0U;
    size_t line_length = 0U;
    int read_status;

    if (!cve_array_load_csv(&cves, CVE_CSV_PATH)) {
        return 1;
    }

    if (!product_array_load_csv(&products, PRODUCT_CSV_PATH)) {
        cve_array_free(&cves);
        return 1;
    }

    if (!cve_array_is_sorted_by_key(&cves) || !product_array_is_sorted_by_key(&products)) {
        fprintf(stderr, "Erro: a base carregada nao esta ordenada por CVE-ID.\n");
        product_array_free(&products);
        cve_array_free(&cves);
        return 1;
    }

    if (!selection_array_load_json(&selections, SELECTIONS_JSON_PATH)) {
        product_array_free(&products);
        cve_array_free(&cves);
        return 1;
    }

    printf(
        "CVE Finder - %zu CVEs carregados (%zu selecao(oes) salva(s) anteriormente).\n",
        cves.count, selections.count
    );
    printf("Digite um CVE-ID (ex.: CVE-2025-0001) ou 'sair' para encerrar.\n\n");

    while (1) {
        char *trimmed;

        printf("> ");
        fflush(stdout);

        read_status = csv_read_line(stdin, &line, &line_capacity, &line_length);
        if (read_status <= 0) {
            putchar('\n');
            break; /* EOF (Ctrl+D) ou erro de leitura */
        }

        trimmed = trim_in_place(line);
        if (trimmed[0] == '\0') {
            continue;
        }
        if (equals_ignoring_case(trimmed, "sair") || equals_ignoring_case(trimmed, "exit")) {
            break;
        }

        {
            FinderResult result = {0};

            if (!finder_search(&cves, &products, trimmed, &result)) {
                printf("Formato invalido. Use CVE-AAAA-NNNN, com o numero em pelo menos 4 digitos (ex.: CVE-2025-0001).\n\n");
                continue;
            }

            print_result(trimmed, &result);

            if (result.found) {
                persist_selection(&selections, &result);
            }
        }
    }

    free(line);
    selection_array_free(&selections);
    product_array_free(&products);
    cve_array_free(&cves);
    return 0;
}
