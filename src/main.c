#include "cve.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    const char *csv_path = "data/cves.csv";
    CVEArray cves = {0};
    size_t published_count = 0U;
    size_t rejected_count = 0U;
    size_t index;

    if (argc > 2) {
        fprintf(stderr, "Uso: %s [caminho_para_cves.csv]\n", argv[0]);
        return 1;
    }
    if (argc == 2) {
        csv_path = argv[1];
    }

    if (!cve_array_load_csv(&cves, csv_path)) {
        return 1;
    }

    for (index = 0U; index < cves.count; ++index) {
        if (cves.items[index].state == CVE_STATE_PUBLISHED) {
            ++published_count;
        } else if (cves.items[index].state == CVE_STATE_REJECTED) {
            ++rejected_count;
        }
    }

    printf("CVEs carregadas: %zu\n", cves.count);
    printf("PUBLISHED: %zu\n", published_count);
    printf("REJECTED: %zu\n", rejected_count);

    cve_array_free(&cves);
    return 0;
}
