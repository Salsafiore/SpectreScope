#include "cache_probe.h"
#include <stdlib.h>
#include <string.h>

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

int calibrate_cache_latency(
    uint32_t iterations,
    CacheCalibrationResult *out_result,
    uint64_t *hit_samples_out,
    uint64_t *miss_samples_out
) {
    if (!out_result || iterations < 16) {
        return -1;
    }

    uint8_t *probe_buf = NULL;
    if (posix_memalign((void **)&probe_buf, PAGE_STRIDE, PAGE_STRIDE * 4) != 0 || !probe_buf) {
        return -2;
    }
    memset(probe_buf, 0xA5, PAGE_STRIDE * 4);

    uint64_t *hits   = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
    uint64_t *misses = (uint64_t *)malloc(sizeof(uint64_t) * iterations);
    if (!hits || !misses) {
        free(probe_buf);
        free(hits);
        free(misses);
        return -3;
    }

    volatile uint8_t *target = probe_buf + (PAGE_STRIDE * 2);

    /* Warm up L1d cache and measure cache hit latency */
    (void)*target;
    for (uint32_t i = 0; i < iterations; i++) {
        (void)*target;
        hits[i] = rdtscp_time_load((const void *)target);
        if (hit_samples_out) {
            hit_samples_out[i] = hits[i];
        }
    }

    /* Flush cache line before each load and measure DRAM/LLC miss latency */
    for (uint32_t i = 0; i < iterations; i++) {
        clflush_line((const void *)target);
        misses[i] = rdtscp_time_load((const void *)target);
        if (miss_samples_out) {
            miss_samples_out[i] = misses[i];
        }
    }

    qsort(hits, iterations, sizeof(uint64_t), cmp_u64);
    qsort(misses, iterations, sizeof(uint64_t), cmp_u64);

    /* Trim top 5% outliers caused by OS scheduler interrupts */
    uint32_t trimmed = (iterations * 95) / 100;
    if (trimmed == 0) trimmed = iterations;

    uint64_t hit_sum = 0, miss_sum = 0;
    for (uint32_t i = 0; i < trimmed; i++) {
        hit_sum  += hits[i];
        miss_sum += misses[i];
    }

    out_result->hit_mean_cycles    = hit_sum / trimmed;
    out_result->hit_median_cycles  = hits[iterations / 2];
    out_result->hit_p90_cycles     = hits[(iterations * 90) / 100];

    out_result->miss_mean_cycles   = miss_sum / trimmed;
    out_result->miss_median_cycles = misses[iterations / 2];
    out_result->miss_p10_cycles    = misses[(iterations * 10) / 100];

    /* Geometric / weighted midpoint threshold biased toward hit p90 */
    uint64_t h_ref = out_result->hit_p90_cycles;
    uint64_t m_ref = out_result->miss_median_cycles;
    if (m_ref > h_ref) {
        out_result->threshold_cycles = h_ref + ((m_ref - h_ref) * 2) / 5;
    } else {
        out_result->threshold_cycles = out_result->hit_median_cycles + 40;
    }

    out_result->separability_ratio = (out_result->hit_median_cycles > 0)
        ? ((double)out_result->miss_median_cycles / (double)out_result->hit_median_cycles)
        : 1.0;
    out_result->sample_count = iterations;

    free(probe_buf);
    free(hits);
    free(misses);
    return 0;
}
