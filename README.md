# SpectreScope

[![Language: C](https://img.shields.io/badge/Language-C99%20%2F%20x86__64%20ASM-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Language: Python](https://img.shields.io/badge/Language-Python%203.10+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform: Linux x86_64](https://img.shields.io/badge/Platform-Linux%20x86__64-orange.svg?logo=linux&logoColor=white)](https://kernel.org)
[![Security Research](https://img.shields.io/badge/Focus-Microarchitecture%20%7C%20Side--Channel%20%7C%20ASLR-red.svg)](#key-capabilities)
[![Tests: Passing](https://img.shields.io/badge/Tests-6%2F6%20Passing%20(100%25)-brightgreen.svg)](#test-suite--hardware-verification)

> **A low-level systems security research toolkit built in C (inline `x86_64` Assembly) and Python for empirical microarchitectural cache side-channel analysis (`Flush+Reload`), userspace Spectre v1 transient execution, statistical Linux kernel ASLR Shannon entropy quantification, and pure-Python ELF64 binary hardening & ROP gadget auditing.**

---

## Short Description (For GitHub Repository "About" Box)

> **x86_64 microarchitectural cache side-channel (Flush+Reload) profiler, isolated Spectre v1 transient execution lab, Linux ASLR bit-entropy quantifier, and ELF64 ROP gadget auditor.**

### Recommended Repository Topics / Tags:
`spectre`, `side-channel-attack`, `flush-reload`, `cache-timing`, `aslr`, `binary-exploitation`, `rop`, `reverse-engineering`, `offensive-security`, `vulnerability-research`, `x86-64-assembly`, `python`

---

## Architectural Overview

```
SpectreScope/
├── Makefile                          # Native build pipeline (shared object & PIE probe)
├── pyproject.toml                    # CLI entrypoint packaging (spectrescope)
├── src/
│   ├── native/
│   │   ├── cache_probe.h             # Serialized rdtscp / clflush / memory-fence primitives
│   │   ├── cache_probe.c             # L1/LLC hit vs DRAM miss profiler & threshold calibration
│   │   ├── spectre_v1_lab.c          # Userspace Spectre v1 (CVE-2017-5753) + Flush+Reload oracle
│   │   └── aslr_probe.c              # Native PIE virtual address layout sampler
│   └── spectrescope/
│       ├── cache.py                  # ctypes FFI bridge & latency distribution statistics
│       ├── aslr.py                   # Per-bit binary Shannon entropy & active bitmask analyzer
│       ├── elf_rop.py                # Standalone 64-bit ELF parser & ROP gadget finder
│       └── cli.py                    # Unified research CLI with ASCII histograms & JSON export
└── tests/
    └── test_spectrescope.py          # End-to-end unit & live hardware integration test suite
```

---

## Technical Mechanics & Capabilities

### 1. Empirical Cache Hierarchy Profiling (`Flush+Reload`)
* **Serialized Memory Load Timing:** Uses inline `x86_64` assembly with strict serialization barriers:
  ```c
  mfence; lfence;
  rdtscp;          // Read cycle counter before load
  lfence;
  movb (%addr), %al;
  lfence;
  rdtscp;          // Read cycle counter after load
  lfence;
  ```
* **Separability Analysis:** Flushes targeted cache lines using `clflush` and compares against cached L1/LLC accesses over $N$ iterations. Automatically discovers the optimal decision threshold (typically ~200–240 cycles) with a **4.0x–7.0x separability ratio** between cached hits (~64–96 cycles) and DRAM misses (~380–450 cycles).

### 2. Isolated Spectre v1 (Bounds-Check Bypass / CVE-2017-5753)
* **Architectural Setup:** Arranges a victim function checking `x < array1_size` with the bounds variable isolated on its own 4KB-aligned memory page.
* **Transient Execution Window:** Evicts `array1_size` to DRAM via `clflush` while keeping the out-of-bounds secret hot in L1d. The CPU's Pattern History Table (PHT) speculatively executes the out-of-bounds branch body inside the Reorder Buffer (ROB):
  $$\text{temp\_sink} \ \&= \text{array2}[\text{array1}[x] \times 4096]$$
* **Prefetcher Evasion:** Reloads the 256-page probe array using a pseudo-random prime stride ($i \times 167 + 13 \pmod{256}$) to defeat hardware streaming and stride prefetchers, achieving **100% byte recovery accuracy** on modern x86_64 architectures.

### 3. Linux Kernel ASLR Shannon Entropy Quantifier
* **Empirical Virtual Memory Sampling:** Spawns a native Position-Independent Executable (`aslr_probe`) repeatedly to collect live randomized base addresses across four memory segments:
  * **PIE (`.text`)**
  * **Stack**
  * **Heap (`brk`)**
  * **Anonymous `mmap` / Shared Libraries**
* **Information-Theoretic Bit Entropy:** Computes the bitwise varying mask ($\text{OR}_{\text{all}} \oplus \text{AND}_{\text{all}}$) and calculates per-bit binary **Shannon entropy**:
  $$H(X) = \sum_{b \in \text{varying}} -\Big(p_1(b)\log_2 p_1(b) + p_0(b)\log_2 p_0(b)\Big)$$
* Distinguishes fixed page-alignment constants (e.g. 12 trailing zero bits for 4KB pages) and scores the feasibility of brute-force vs. partial pointer overwrite attacks.

### 4. ELF64 Binary Hardening & ROP Gadget Auditor
* **Zero-Dependency ELF Parser:** Custom binary parser reading 64-bit ELF headers and program headers directly via Python's `struct`.
* **Mitigation Inspection:**
  * `PIE`: Evaluates `ET_DYN` with `DF_1_PIE`
  * `NX`: Verifies `PT_GNU_STACK` executable flag status
  * `RELRO`: Analyzes `PT_GNU_RELRO` coupled with `DT_FLAGS` / `DF_1_NOW` (distinguishing **Full RELRO** from **Partial RELRO**)
  * `Stack Canaries`: Scans symbol and relocation tables for `__stack_chk_fail`
* **ROP Scanner:** Scans executable `PT_LOAD` segments for critical 64-bit exploit primitives (`pop rdi; ret`, `pop rsi; ret`, `pop rdx; ret`, `syscall; ret`, `leave; ret`, `call rax`).

---

## Quick Start & Usage

### 1. Build the Native Components
```bash
git clone https://github.com/Salsafiore/SpectreScope.git
cd SpectreScope
make
```

### 2. Run the Full Research Suite
```bash
PYTHONPATH=src python3 -m spectrescope.cli all
```

### 3. Run Individual Research Modules

#### A. Cache Hierarchy Profiler
```bash
PYTHONPATH=src python3 -m spectrescope.cli calibrate -n 2000
```
```text
========================================================================
 SpectreScope :: x86_64 Cache Hierarchy Latency Profiler (rdtscp + clflush)
========================================================================
  Samples per class    : 2000
  Cache Hit  (median)  : 64 cycles (mean: 65, p90: 64)
  Cache Miss (median)  : 448 cycles (mean: 441, p10: 416)
  Optimal Threshold    : 217 cycles
  Separability Ratio   : 7.00x (Miss / Hit)
------------------------------------------------------------------------
  Cycle Latency Band  | L1/LLC Hits       | DRAM Misses
  --------------------+-------------------+-------------------
    0-40  cycles      |                   |                  
   41-80  cycles      | ##############    |                  
   81-120 cycles      | #                 |                  
  121-160 cycles      |                   |                  
  161-220 cycles      |                   |                   <-- threshold
  221-300 cycles      |                   |                  
  301-500 cycles      |                   | ::::::::::::::   
    >501 cycles       |                   | :                
========================================================================
```

#### B. Spectre v1 Transient Execution Recovery
```bash
PYTHONPATH=src python3 -m spectrescope.cli spectre-sim -t 35
```
```text
========================================================================
 SpectreScope :: Spectre v1 (Bounds-Check Bypass) + Flush+Reload Lab
========================================================================
  Victim array1 Base   : 0x00007fbdba77c004
  Target Secret Base   : 0x00007fbdba77c054 (OOB offset: +80 bytes)
  Decision Threshold   : 204 cycles
  Expected Secret      : FLAG{SPECULATIVE_ASLR_LEAK_0x7FFF}
  Recovered Secret     : FLAG{SPECULATIVE_ASLR_LEAK_0x7FFF}
  Recovery Accuracy    : 100.0%
========================================================================
```

#### C. Linux ASLR Entropy Analysis
```bash
PYTHONPATH=src python3 -m spectrescope.cli aslr -s 48
```
```text
========================================================================
 SpectreScope :: Linux x86_64 ASLR Entropy & Pointer-Leak Quantifier
========================================================================
  kernel.randomize_va_space : 2
  Spawned Process Samples   : 48
------------------------------------------------------------------------
  [PIE (.text)]
    Address Range       : 0x00005557febfa090 .. 0x00005651eddce090
    Varying Bitmask     : 0x000003fffffff000 (30 active bits)
    Shannon Entropy     : 29.21 bits (page align: 12 bits)
    Security Assessment : STRONG (>=24 bits: brute-force impractical without info leak)
  [Stack]
    Address Range       : 0x00007ffc2030414c .. 0x00007ffff664cf8c
    Varying Bitmask     : 0x00000003fffffff0 (30 active bits)
    Shannon Entropy     : 29.51 bits (page align: 4 bits)
    Security Assessment : STRONG (>=24 bits: brute-force impractical without info leak)
========================================================================
```

#### D. ELF Binary Mitigation & ROP Audit
```bash
PYTHONPATH=src python3 -m spectrescope.cli elf-audit /bin/ls
```

---

## Test Suite & Hardware Verification

All test suites run against real hardware instruction counters and verify:
1. Native C parameter bounds checking and NULL pointer safety.
2. Cycle-accurate L1 vs. DRAM latency separability.
3. Out-of-bounds speculative execution byte recovery.
4. Mathematical Shannon entropy calculations and active bitmask alignment.
5. ELF mitigation auditing across synthetic hardened (`100/100`) and unhardened (`0/100`) binaries.
6. CLI execution and valid JSON schema serialization.

Run the test suite:
```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

---

## Research References

* **Spectre Attacks: Exploiting Speculative Execution** (Kocher et al., IEEE S&P 2019)
* **FLUSH+RELOAD: A High Resolution, Low Noise, L3 Cache Side-Channel Attack** (Yarom & Falkner, USENIX Security 2014)
* **ASLR Smack & Laugh Reference** (Brumley et al.)

---

## Author

**Gunmay Pachauri**
* **GitHub:** [@salsafiore](https://github.com/salsafiore)
* **Role:** Offensive Security & Vulnerability Researcher • CRTA-Certified
* **Email:** [gunmaypachauri566@gmail.com](mailto:gunmaypachauri566@gmail.com)
* **Hack The Box:** `@lilskele`

---

## License

This project is licensed under the [MIT License](LICENSE).
