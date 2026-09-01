#include "cve.h"
#include "search.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

#define CVE_CSV_PATH "data/cves.csv"
#define BENCHMARK_JSON_PATH "output/benchmark.json"
#define QUERIES_PER_SIZE 200U /* metade acerto, metade erro */
#define REPEATS 20U

typedef struct {
    uint32_t year;
    uint32_t number;
} Query;

typedef struct {
    size_t n;
    double avg_comparisons_binary;
    double avg_comparisons_linear;
    double avg_time_us_binary;
    double avg_time_us_linear;
} SizeResult;

static const double FRACTIONS[] = { 0.05, 0.10, 0.25, 0.50, 0.75, 1.00 };
#define FRACTION_COUNT (sizeof(FRACTIONS) / sizeof(FRACTIONS[0]))

static double elapsed_seconds(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec)
        + (double)(end.tv_nsec - start.tv_nsec) / 1e9;
}


static void build_queries(const CVEArray *subset, Query *queries, size_t count)
{
    size_t hits = count / 2U;
    size_t misses = count - hits;
    size_t stride = (hits == 0U) ? 1U : (subset->count / hits);
    size_t i;

    if (stride == 0U) {
        stride = 1U;
    }

    for (i = 0U; i < hits; ++i) {
        size_t index = (i * stride) % subset->count;

        queries[i].year = subset->items[index].year;
        queries[i].number = subset->items[index].number;
    }
    for (i = 0U; i < misses; ++i) {
        queries[hits + i].year = 2099U;
        queries[hits + i].number = (uint32_t)(i + 1U);
    }
}

static SizeResult run_size(const CVEArray *full, double fraction)
{
    size_t size = (size_t)((double)full->count * fraction);
    CVEArray subset;
    Query queries[QUERIES_PER_SIZE];
    size_t total_comparisons_binary = 0U;
    size_t total_comparisons_linear = 0U;
    struct timespec t0;
    struct timespec t1;
    double time_binary;
    double time_linear;
    size_t total_ops = (size_t)REPEATS * QUERIES_PER_SIZE;
    size_t r;
    size_t q;
    SizeResult result = {0};

    if (size == 0U) {
        size = 1U;
    }
    if (size > full->count) {
        size = full->count;
    }

    subset.items = full->items;
    subset.count = size;
    subset.capacity = size;

    build_queries(&subset, queries, QUERIES_PER_SIZE);

    timespec_get(&t0, TIME_UTC);
    for (r = 0U; r < REPEATS; ++r) {
        for (q = 0U; q < QUERIES_PER_SIZE; ++q) {
            size_t index;
            size_t comparisons = 0U;

            cve_array_binary_search_counted(
                &subset, queries[q].year, queries[q].number, &index, &comparisons
            );
            total_comparisons_binary += comparisons;
        }
    }
    timespec_get(&t1, TIME_UTC);
    time_binary = elapsed_seconds(t0, t1);

    timespec_get(&t0, TIME_UTC);
    for (r = 0U; r < REPEATS; ++r) {
        for (q = 0U; q < QUERIES_PER_SIZE; ++q) {
            size_t index;
            size_t comparisons = 0U;

            cve_array_linear_search_counted(
                &subset, queries[q].year, queries[q].number, &index, &comparisons
            );
            total_comparisons_linear += comparisons;
        }
    }
    timespec_get(&t1, TIME_UTC);
    time_linear = elapsed_seconds(t0, t1);

    result.n = size;
    result.avg_comparisons_binary = (double)total_comparisons_binary / (double)total_ops;
    result.avg_comparisons_linear = (double)total_comparisons_linear / (double)total_ops;
    result.avg_time_us_binary = time_binary / (double)total_ops * 1e6;
    result.avg_time_us_linear = time_linear / (double)total_ops * 1e6;
    return result;
}

static void print_table(const SizeResult *results, size_t count)
{
    size_t i;

    printf(
        "%10s | %10s | %10s | %12s | %12s | %9s\n",
        "tamanho N", "cmp bin", "cmp lin", "us/busca bin", "us/busca lin", "speedup"
    );
    printf("-----------+------------+------------+--------------+--------------+---------\n");

    for (i = 0U; i < count; ++i) {
        const SizeResult *r = &results[i];
        double speedup = (r->avg_time_us_binary > 0.0)
            ? (r->avg_time_us_linear / r->avg_time_us_binary)
            : 0.0;

        printf(
            "%10zu | %10.1f | %10.1f | %12.4f | %12.4f | %8.1fx\n",
            r->n, r->avg_comparisons_binary, r->avg_comparisons_linear,
            r->avg_time_us_binary, r->avg_time_us_linear, speedup
        );
    }
}

static void ensure_output_directory(void)
{
#ifdef _WIN32
    (void)_mkdir("output");
#else
    (void)mkdir("output", 0755);
#endif
}

static int write_json(const SizeResult *results, size_t count, size_t dataset_size)
{
    FILE *file;
    size_t i;

    ensure_output_directory();

    file = fopen(BENCHMARK_JSON_PATH, "wb");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "{\n");
    fprintf(file, "  \"dataset_size\": %zu,\n", dataset_size);
    fprintf(file, "  \"queries_per_size\": %u,\n", QUERIES_PER_SIZE);
    fprintf(file, "  \"repeats\": %u,\n", REPEATS);
    fprintf(file, "  \"results\": [\n");

    for (i = 0U; i < count; ++i) {
        const SizeResult *r = &results[i];

        fprintf(file, "    {\n");
        fprintf(file, "      \"n\": %zu,\n", r->n);
        fprintf(file, "      \"avg_comparisons_binary\": %.2f,\n", r->avg_comparisons_binary);
        fprintf(file, "      \"avg_comparisons_linear\": %.2f,\n", r->avg_comparisons_linear);
        fprintf(file, "      \"avg_time_us_binary\": %.6f,\n", r->avg_time_us_binary);
        fprintf(file, "      \"avg_time_us_linear\": %.6f\n", r->avg_time_us_linear);
        fprintf(file, i + 1U < count ? "    },\n" : "    }\n");
    }

    fprintf(file, "  ]\n");
    fprintf(file, "}\n");

    {
        int success = !ferror(file);

        if (fclose(file) != 0) {
            success = 0;
        }
        return success;
    }
}

int main(void)
{
    CVEArray cves = {0};
    SizeResult results[FRACTION_COUNT];
    size_t i;

    if (!cve_array_load_csv(&cves, CVE_CSV_PATH)) {
        return 1;
    }
    if (!cve_array_is_sorted_by_key(&cves)) {
        fprintf(stderr, "Erro: %s nao esta ordenado por CVE-ID.\n", CVE_CSV_PATH);
        cve_array_free(&cves);
        return 1;
    }

    printf("Benchmark: busca binaria vs busca linear (base completa: %zu CVEs)\n", cves.count);
    printf(
        "Cada linha: media de %u buscas (metade acerto, metade erro), repetidas %u vezes.\n\n",
        QUERIES_PER_SIZE, REPEATS
    );

    for (i = 0U; i < FRACTION_COUNT; ++i) {
        results[i] = run_size(&cves, FRACTIONS[i]);
    }

    print_table(results, FRACTION_COUNT);

    if (write_json(results, FRACTION_COUNT, cves.count)) {
        printf("\nResultados gravados em %s (para o frontend comparar as duas buscas)\n", BENCHMARK_JSON_PATH);
    } else {
        fprintf(stderr, "\nAviso: nao foi possivel gravar %s.\n", BENCHMARK_JSON_PATH);
    }

    cve_array_free(&cves);
    return 0;
}
