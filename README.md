# SpectreScope

**x86_64 Microarchitectural Cache Side-Channel (`Flush+Reload`), ASLR Entropy Quantifier & ELF64 ROP Security Analyzer**

`SpectreScope` is a low-level systems security research toolkit built in **C (with inline `x86_64` Assembly)** and **Python**. It provides empirical measurement primitives for microarchitectural cache timing side-channels (`rdtscp` + `clflush`), an isolated userspace **Spectre v1 (Bounds-Check Bypass)** transient execution lab, statistical **Linux ASLR bit-entropy quantification**, and a pure-Python **ELF64 binary hardening & ROP gadget auditor**.

---

## Architecture

```
SpectreScope/
├── Makefile                        # Builds native C/x86_64 shared library & PIE ASLR probe binary
├── pyproject.toml                  # Python CLI packaging (`spectrescope`)
├── src/
│   ├── native/
│   │   ├── cache_probe.h           # Serialized x86_64 rdtscp / mfence / lfence / clflush primitives
│   │   ├── cache_probe.c           # L1/LLC hit vs. DRAM miss profiler & threshold auto-calibrator
│   │   ├── spectre_v1_lab.c        # Userspace Spectre v1 (CVE-2017-5753) + Flush+Reload oracle
│   │   └── aslr_probe.c            # Native PIE/Stack/Heap/mmap virtual address sampler
│   └── spectrescope/
│       ├── cache.py                # ctypes FFI bridge to libspectrescope.so
│       ├── aslr.py                 # Per-bit binary Shannon entropy & varying bitmask analyzer
│       ├── elf_rop.py              # ELF64 mitigation auditor (PIE/NX/RELRO/Canary) & ROP scanner
│       └── cli.py                  # Unified CLI with ASCII histograms & JSON export
└── tests/
    └── test_spectrescope.py        # Automated test suite
```

---

## Key Capabilities

1. **x86_64 Cache Hierarchy Latency Profiler (`spectrescope calibrate`)**
   * Uses serialized `mfence; lfence; rdtscp` instruction sequences and `clflush` cache-line eviction to measure exact CPU cycle distributions for L1d/LLC hits versus DRAM misses.
   * Automatically computes the optimal `Flush+Reload` decision threshold and renders an ASCII cycle-latency histogram.

2. **Spectre v1 + Flush+Reload Lab (`spectre-sim`)**
   * Models out-of-bounds speculative memory reads across a 256-page (`256 * 4096` byte) probe array using branch-predictor mistraining and prime-stride (`167`) reload probing to defeat hardware stride prefetchers.
   * Reports per-byte hit ratios, runner-up noise margins, average cycle latencies, and recovery confidence.

3. **Linux ASLR Entropy Quantifier (`spectrescope aslr`)**
   * Spawns a native Position-Independent Executable (`aslr_probe`) across $N$ trials to sample real kernel virtual address randomization across `PIE (.text)`, `Stack`, `Heap (brk)`, and `mmap` regions.
   * Computes active varying bitmasks, page-alignment constants, and summed per-bit **Shannon entropy** to evaluate resistance against pointer-leak and brute-force attacks.

4. **ELF64 Mitigation & ROP Gadget Auditor (`spectrescope elf-audit`)**
   * Parses 64-bit ELF program headers (`PT_GNU_STACK`, `PT_GNU_RELRO`, `PT_DYNAMIC`, `PT_LOAD`) from scratch without external dependencies.
   * Audits `PIE`, `NX`, `Full/Partial RELRO`, `Stack Canaries`, and `RWX` segments, and scans executable segments for `x86_64` ROP gadgets (`pop rdi; ret`, `pop rsi; ret`, `syscall; ret`, `leave; ret`, etc.).

---

## Quick Start

```bash
# 1. Compile native C / x86_64 shared library and PIE probe
make

# 2. Run the full security research benchmark suite
PYTHONPATH=src python3 -m spectrescope.cli all

# 3. Run individual modules (supports --json for automation)
PYTHONPATH=src python3 -m spectrescope.cli calibrate -n 2000
PYTHONPATH=src python3 -m spectrescope.cli spectre-sim -t 40
PYTHONPATH=src python3 -m spectrescope.cli aslr -s 64
PYTHONPATH=src python3 -m spectrescope.cli elf-audit /bin/ls

# 4. Run unit & integration tests
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
# SpectreScope
