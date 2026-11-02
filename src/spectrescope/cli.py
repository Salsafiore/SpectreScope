import argparse
import dataclasses
import json
import sys
from pathlib import Path

from spectrescope.aslr import analyze_aslr_entropy
from spectrescope.cache import run_cache_calibration, run_spectre_v1_simulation
from spectrescope.elf_rop import audit_elf_binary


def _render_ascii_histogram(hit_samples: list[int], miss_samples: list[int], threshold: int) -> str:
    buckets = [
        (0, 40),
        (41, 80),
        (81, 120),
        (121, 160),
        (161, 220),
        (221, 300),
        (301, 500),
        (501, 99999),
    ]
    lines = ["  Cycle Latency Band  | L1/LLC Hits       | DRAM Misses"]
    lines.append("  --------------------+-------------------+-------------------")
    total_h = max(1, len(hit_samples))
    total_m = max(1, len(miss_samples))

    for lo, hi in buckets:
        h_cnt = sum(1 for x in hit_samples if lo <= x <= hi)
        m_cnt = sum(1 for x in miss_samples if lo <= x <= hi)
        h_bar = "#" * int((h_cnt / total_h) * 16)
        m_bar = ":" * int((m_cnt / total_m) * 16)
        label = f"{lo:>3}-{hi:<3} cycles" if hi < 90000 else f"  >{lo:<3} cycles"
        marker = " <-- threshold" if lo <= threshold <= hi else ""
        lines.append(f"  {label:<19} | {h_bar:<17} | {m_bar:<17}{marker}")
    return "\n".join(lines)


def cmd_calibrate(args: argparse.Namespace) -> int:
    prof = run_cache_calibration(iterations=args.iterations)
    if args.json:
        data = dataclasses.asdict(prof)
        data.pop("hit_samples", None)
        data.pop("miss_samples", None)
        print(json.dumps(data, indent=2))
        return 0

    print("=" * 72)
    print(" SpectreScope :: x86_64 Cache Hierarchy Latency Profiler (rdtscp + clflush)")
    print("=" * 72)
    print(f"  Samples per class    : {prof.sample_count}")
    print(f"  Cache Hit  (median)  : {prof.hit_median_cycles} cycles (mean: {prof.hit_mean_cycles}, p90: {prof.hit_p90_cycles})")
    print(f"  Cache Miss (median)  : {prof.miss_median_cycles} cycles (mean: {prof.miss_mean_cycles}, p10: {prof.miss_p10_cycles})")
    print(f"  Optimal Threshold    : {prof.threshold_cycles} cycles")
    print(f"  Separability Ratio   : {prof.separability_ratio:.2f}x (Miss / Hit)")
    print("-" * 72)
    print(_render_ascii_histogram(prof.hit_samples, prof.miss_samples, prof.threshold_cycles))
    print("=" * 72)
    return 0


def cmd_spectre_sim(args: argparse.Namespace) -> int:
    report = run_spectre_v1_simulation(
        trials_per_byte=args.trials,
        threshold_cycles=args.threshold,
    )
    if args.json:
        print(json.dumps(dataclasses.asdict(report), indent=2))
        return 0

    print("=" * 72)
    print(" SpectreScope :: Spectre v1 (Bounds-Check Bypass) + Flush+Reload Lab")
    print("=" * 72)
    print(f"  Victim array1 Base   : 0x{report.array1_base:016x}")
    print(f"  Target Secret Base   : 0x{report.secret_base:016x} (OOB offset: {report.oob_delta:+d} bytes)")
    print(f"  Decision Threshold   : {report.threshold_cycles} cycles")
    print(f"  Expected Secret      : {report.target_secret}")
    print(f"  Recovered Secret     : {report.recovered_secret}")
    print(f"  Recovery Accuracy    : {report.accuracy * 100:.1f}%")
    print("-" * 72)
    print("  Idx | Byte | Char | Hits/Trials | Runner-Up | Avg Hit Cycles | Confidence")
    print("  ----+------+------+-------------+-----------+----------------+-----------")
    for b in report.byte_results[: args.max_rows]:
        print(
            f"  {b.offset:>3} | 0x{b.recovered_byte:02x} |  '{b.recovered_char}' | "
            f"{b.best_hits:>4}/{b.total_trials:<6} | {b.runner_up_hits:>9} | "
            f"{b.best_avg_cycles:>8} cyc   | {b.confidence * 100:>6.1f}%"
        )
    if len(report.byte_results) > args.max_rows:
        print(f"  ... ({len(report.byte_results) - args.max_rows} additional bytes omitted; use --max-rows to view all)")
    print("=" * 72)
    return 0


def cmd_aslr(args: argparse.Namespace) -> int:
    report = analyze_aslr_entropy(samples=args.samples)
    if args.json:
        print(json.dumps(dataclasses.asdict(report), indent=2))
        return 0

    print("=" * 72)
    print(" SpectreScope :: Linux x86_64 ASLR Entropy & Pointer-Leak Quantifier")
    print("=" * 72)
    print(f"  kernel.randomize_va_space : {report.kernel_randomize_va_space}")
    print(f"  Spawned Process Samples   : {report.samples}")
    print("-" * 72)
    for name, reg in report.regions.items():
        print(f"  [{name}]")
        print(f"    Address Range       : 0x{reg.min_addr:016x} .. 0x{reg.max_addr:016x}")
        print(f"    Varying Bitmask     : 0x{reg.varying_mask:016x} ({reg.varying_bits_count} active bits)")
        print(f"    Shannon Entropy     : {reg.shannon_entropy_bits:.2f} bits (page align: {reg.page_alignment_bits} bits)")
        print(f"    Security Assessment : {reg.assessment}")
    print("=" * 72)
    return 0


def cmd_elf_audit(args: argparse.Namespace) -> int:
    target = args.binary
    if target is None:
        root = Path(__file__).resolve().parents[2]
        target = str(root / "build" / "aslr_probe")

    report = audit_elf_binary(target, max_gadgets_per_type=args.max_gadgets)
    if args.json:
        print(json.dumps(dataclasses.asdict(report), indent=2))
        return 0

    print("=" * 72)
    print(" SpectreScope :: ELF64 Hardening & ROP / ASLR-Bypass Primitive Auditor")
    print("=" * 72)
    print(f"  Target Binary        : {report.path} ({report.arch})")
    print(f"  PIE (ASLR Support)   : {'ENABLED' if report.pie_enabled else 'DISABLED'}")
    print(f"  NX (Non-Exec Stack)  : {'ENABLED' if report.nx_enabled else 'DISABLED'}")
    print(f"  RELRO Mode           : {report.relro_mode}")
    print(f"  Stack Canary         : {'DETECTED' if report.stack_canary else 'NOT FOUND'}")
    print(f"  RWX Segments         : {report.rwx_segments}")
    print(f"  Hardening Score      : {report.aslr_leak_resistance_score}/100")
    print(f"  Imported I/O Symbols : {', '.join(report.leak_primitives) if report.leak_primitives else 'None'}")
    print("-" * 72)
    print("  Discovered x86_64 ROP Gadgets:")
    for g in report.gadgets:
        print(f"    0x{g.vaddr:08x} : {g.mnemonic:<26} [{g.raw_hex}]")
    print("=" * 72)
    return 0


def cmd_all(args: argparse.Namespace) -> int:
    cmd_calibrate(argparse.Namespace(iterations=1500, json=False))
    print()
    cmd_spectre_sim(argparse.Namespace(trials=35, threshold=None, max_rows=12, json=False))
    print()
    cmd_aslr(argparse.Namespace(samples=32, json=False))
    print()
    cmd_elf_audit(argparse.Namespace(binary=None, max_gadgets=2, json=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spectrescope",
        description="SpectreScope: x86_64 Cache Side-Channel (Flush+Reload), ASLR Entropy & ELF64 ROP Analyzer",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_cal = sub.add_parser("calibrate", help="Profile CPU L1/LLC cache hit vs. DRAM miss latency via rdtscp/clflush")
    p_cal.add_argument("-n", "--iterations", type=int, default=2000, help="Number of probe iterations (default: 2000)")
    p_cal.add_argument("--json", action="store_true", help="Emit JSON output")
    p_cal.set_defaults(func=cmd_calibrate)

    p_spec = sub.add_parser("spectre-sim", help="Run isolated userspace Spectre v1 + Flush+Reload byte recovery lab")
    p_spec.add_argument("-t", "--trials", type=int, default=40, help="Trials per secret byte (default: 40)")
    p_spec.add_argument("--threshold", type=int, default=None, help="Override cache hit cycle threshold")
    p_spec.add_argument("--max-rows", type=int, default=16, help="Max byte rows to display in table")
    p_spec.add_argument("--json", action="store_true", help="Emit JSON output")
    p_spec.set_defaults(func=cmd_spectre_sim)

    p_aslr = sub.add_parser("aslr", help="Quantify Linux kernel ASLR bit-level Shannon entropy across memory regions")
    p_aslr.add_argument("-s", "--samples", type=int, default=48, help="Process spawn samples (default: 48)")
    p_aslr.add_argument("--json", action="store_true", help="Emit JSON output")
    p_aslr.set_defaults(func=cmd_aslr)

    p_elf = sub.add_parser("elf-audit", help="Audit 64-bit ELF binary mitigations (PIE/NX/RELRO/Canary) & scan ROP gadgets")
    p_elf.add_argument("binary", nargs="?", default=None, help="Path to ELF64 binary (default: build/aslr_probe)")
    p_elf.add_argument("--max-gadgets", type=int, default=3, help="Max gadgets per instruction signature")
    p_elf.add_argument("--json", action="store_true", help="Emit JSON output")
    p_elf.set_defaults(func=cmd_elf_audit)

    p_all = sub.add_parser("all", help="Run full microarchitectural + ASLR + ELF security research suite")
    p_all.set_defaults(func=cmd_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
