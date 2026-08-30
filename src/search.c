#include "search.h"

int cve_array_binary_search(
    const CVEArray *array,
    uint32_t year,
    uint32_t number,
    size_t *out_index
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
        int comparison = cve_compare_key(&array->items[mid], &target);

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
