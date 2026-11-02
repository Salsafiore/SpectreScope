#ifndef SPECTRESCOPE_CACHE_PROBE_H
#define SPECTRESCOPE_CACHE_PROBE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CACHE_LINE_SIZE 64
#define PAGE_STRIDE     4096
#define PROBE_ALPHABET  256

typedef struct {
    uint64_t hit_mean_cycles;
    uint64_t hit_median_cycles;
    uint64_t hit_p90_cycles;
    uint64_t miss_mean_cycles;
    uint64_t miss_median_cycles;
    uint64_t miss_p10_cycles;
    uint64_t threshold_cycles;
    double   separability_ratio;
    uint32_t sample_count;
} CacheCalibrationResult;

typedef struct {
    uint8_t  recovered_byte;
    uint8_t  runner_up_byte;
    uint32_t best_hits;
    uint32_t runner_up_hits;
    uint32_t total_trials;
    uint64_t best_avg_cycles;
    double   confidence;
} SpectreByteResult;

typedef struct {
    uintptr_t text_addr;
    uintptr_t stack_addr;
    uintptr_t heap_addr;
    uintptr_t mmap_addr;
} AslrSample;

/*
 * Measure exact CPU clock cycles required to load a single byte from `addr`
 * using serialized x86_64 rdtscp + memory fences.
 */
static inline uint64_t rdtscp_time_load(const void *addr) {
    uint32_t lo1, hi1, lo2, hi2;
    __asm__ __volatile__ (
        "mfence\n\t"
        "lfence\n\t"
        "rdtscp\n\t"
        "lfence\n\t"
        "movl %%eax, %0\n\t"
        "movl %%edx, %1\n\t"
        "movb (%4), %%al\n\t"
        "lfence\n\t"
        "rdtscp\n\t"
        "lfence\n\t"
        "movl %%eax, %2\n\t"
        "movl %%edx, %3\n\t"
        : "=&r"(lo1), "=&r"(hi1), "=&r"(lo2), "=&r"(hi2)
        : "r"(addr)
        : "rax", "rcx", "rdx", "memory"
    );
    uint64_t start = ((uint64_t)hi1 << 32) | lo1;
    uint64_t end   = ((uint64_t)hi2 << 32) | lo2;
    return end - start;
}

/*
 * Evict the cache line containing `addr` from all levels of the CPU cache
 * hierarchy (L1d, L2, LLC) using the x86_64 clflush instruction.
 */
static inline void clflush_line(const void *addr) {
    __asm__ __volatile__ (
        "clflush (%0)\n\t"
        "mfence\n\t"
        :
        : "r"(addr)
        : "memory"
    );
}

int calibrate_cache_latency(
    uint32_t iterations,
    CacheCalibrationResult *out_result,
    uint64_t *hit_samples_out,
    uint64_t *miss_samples_out
);

int spectre_v1_recover_byte(
    size_t target_offset,
    uint32_t trials,
    uint64_t threshold_cycles,
    SpectreByteResult *out_result
);

int spectre_v1_recover_secret(
    uint32_t trials_per_byte,
    uint64_t threshold_cycles,
    char *out_buf,
    size_t buf_len,
    SpectreByteResult *byte_results_out
);

const char *spectre_v1_get_target_secret(size_t *out_len);

uintptr_t spectre_v1_get_array1_base(void);
uintptr_t spectre_v1_get_secret_base(void);

#ifdef __cplusplus
}
#endif

#endif /* SPECTRESCOPE_CACHE_PROBE_H */
