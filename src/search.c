#include "search.h"

static void count_comparison(size_t *out_comparisons)
{
    if (out_comparisons != NULL) {
        ++(*out_comparisons);
    }
}

int cve_array_binary_search_counted(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index,
    size_t *out_comparisons
)
{
    CVE target = {0};
    size_t low;
    size_t high;

    if (array == NULL || out_index == NULL) {
        return 0;
    }

    target.year = year;
    target.number = number;

    low = 0U;
    high = array->count;

    while (low < high) {
        size_t mid = low + (high - low) / 2U; /* evita overflow de low+high */
        int comparison;

        count_comparison(out_comparisons);
        comparison = cve_compare_key(&array->items[mid], &target);

        if (comparison == 0) {
            *out_index = mid;
            return 1;
        }

        if (comparison < 0) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }

    return 0;
}

int cve_array_binary_search(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index
)
{
    return cve_array_binary_search_counted(array, year, number, out_index, NULL);
}

int cve_array_linear_search_counted(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index,
    size_t *out_comparisons
)
{
    CVE target = {0};
    size_t index;

    if (array == NULL || out_index == NULL) {
        return 0;
    }

    target.year = year;
    target.number = number;

    for (index = 0U; index < array->count; ++index) {
        count_comparison(out_comparisons);
        if (cve_compare_key(&array->items[index], &target) == 0) {
            *out_index = index;
            return 1;
        }
    }

    return 0;
}

int cve_array_linear_search(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index
)
{
    return cve_array_linear_search_counted(array, year, number, out_index, NULL);
}
