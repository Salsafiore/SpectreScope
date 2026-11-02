import ctypes
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from spectrescope.aslr import _compute_region_entropy, analyze_aslr_entropy
from spectrescope.cache import (
    _CacheCalibrationResult,
    _SpectreByteResult,
    load_native_lib,
    run_cache_calibration,
    run_spectre_v1_simulation,
)
from spectrescope.cli import main as cli_main
from spectrescope.elf_rop import audit_elf_binary


class TestSpectreScopeComprehensive(unittest.TestCase):
    """End-to-end unit and integration tests for SpectreScope."""

    def test_01_native_c_error_handling_edge_cases(self) -> None:
        """Verify C native functions reject invalid parameters safely."""
        lib = load_native_lib()
        cal_res = _CacheCalibrationResult()
        # iterations < 16 must return -1
        rc = lib.calibrate_cache_latency(5, ctypes.byref(cal_res), None, None)
        self.assertEqual(rc, -1)

        # NULL output pointer must return -1
        rc_null = lib.calibrate_cache_latency(100, None, None, None)
        self.assertEqual(rc_null, -1)

    def test_02_cache_calibration_hardware_separability(self) -> None:
        """Verify rdtscp + clflush cache profiler distinguishes L1/LLC hits from DRAM misses."""
        prof = run_cache_calibration(iterations=1000)
        self.assertEqual(prof.sample_count, 1000)
        self.assertEqual(len(prof.hit_samples), 1000)
        self.assertEqual(len(prof.miss_samples), 1000)
        self.assertGreater(prof.miss_median_cycles, prof.hit_median_cycles)
        self.assertGreater(prof.separability_ratio, 1.5)
        self.assertGreater(prof.threshold_cycles, prof.hit_median_cycles)
        self.assertLess(prof.threshold_cycles, prof.miss_median_cycles)

    def test_03_pure_hardware_spectre_v1_transient_recovery(self) -> None:
        """Verify pure hardware Spectre v1 speculative execution recovers the out-of-bounds secret."""
        report = run_spectre_v1_simulation(trials_per_byte=45)
        self.assertEqual(report.target_secret, "FLAG{SPECULATIVE_ASLR_LEAK_0x7FFF}")
        self.assertEqual(len(report.byte_results), len(report.target_secret))
        self.assertGreater(report.oob_delta, 0)
        self.assertGreaterEqual(report.accuracy, 0.90)
        for b in report.byte_results:
            self.assertGreaterEqual(b.confidence, 0.0)
            self.assertLessEqual(b.confidence, 1.0)
            self.assertGreaterEqual(b.total_trials, 45)

    def test_04_aslr_entropy_live_sampling_and_math(self) -> None:
        """Verify live Linux ASLR process sampling and per-bit Shannon entropy calculations."""
        report = analyze_aslr_entropy(samples=24)
        self.assertEqual(report.samples, 24)
        self.assertIn(report.kernel_randomize_va_space, (0, 1, 2))
        for region_name in ("PIE (.text)", "Stack", "Heap (brk)", "mmap / Shared Libs"):
            self.assertIn(region_name, report.regions)
            reg = report.regions[region_name]
            self.assertEqual(reg.sample_count, 24)
            if report.kernel_randomize_va_space == 2:
                self.assertGreater(reg.varying_bits_count, 16)
                self.assertGreater(reg.shannon_entropy_bits, 12.0)

        # Deterministic synthetic entropy verification:
        # Static addresses -> 0 bits entropy
        static_reg = _compute_region_entropy("Static", [0x401000] * 16)
        self.assertEqual(static_reg.varying_bits_count, 0)
        self.assertEqual(static_reg.shannon_entropy_bits, 0.0)
        self.assertIn("DISABLED", static_reg.assessment)

        # 4 perfectly balanced independent bits at page shift 12 -> 4.00 bits Shannon entropy
        balanced_addrs = [0x550000000000 | (i << 12) for i in range(16)]
        bal_reg = _compute_region_entropy("Balanced4Bit", balanced_addrs)
        self.assertEqual(bal_reg.varying_bits_count, 4)
        self.assertAlmostEqual(bal_reg.shannon_entropy_bits, 4.0, places=2)
        self.assertEqual(bal_reg.page_alignment_bits, 12)

    def test_05_elf64_hardened_vs_unhardened_binaries(self) -> None:
        """Compile synthetic C binaries with different hardening flags and verify ELF64 auditor."""
        c_src = r"""
        #include <stdio.h>
        #include <string.h>
        void gadget_bank(void) {
            __asm__ __volatile__(
                "pop %%rdi; ret\n\t"
                "pop %%rsi; ret\n\t"
                "pop %%rdx; ret\n\t"
                "syscall; ret\n\t"
                : : : "rdi", "rsi", "rdx"
            );
        }
        int main(int argc, char **argv) {
            char buf[64];
            if (argc > 1) strcpy(buf, argv[1]);
            puts(buf);
            return 0;
        }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            src_file = tmp / "test_bin.c"
            src_file.write_text(c_src)

            # 1. Fully hardened binary (PIE + Full RELRO + NX + Stack Canary)
            hard_bin = tmp / "hardened"
            subprocess.run(
                [
                    "gcc",
                    "-O1",
                    "-fPIE",
                    "-pie",
                    "-fstack-protector-all",
                    "-Wl,-z,relro,-z,now",
                    "-Wl,-z,noexecstack",
                    str(src_file),
                    "-o",
                    str(hard_bin),
                ],
                check=True,
            )
            hard_rep = audit_elf_binary(hard_bin)
            self.assertEqual(hard_rep.arch, "x86_64")
            self.assertTrue(hard_rep.pie_enabled)
            self.assertTrue(hard_rep.nx_enabled)
            self.assertEqual(hard_rep.relro_mode, "Full RELRO")
            self.assertTrue(hard_rep.stack_canary)
            self.assertEqual(hard_rep.aslr_leak_resistance_score, 100)
            self.assertIn("puts", hard_rep.leak_primitives)
            self.assertIn("strcpy", hard_rep.leak_primitives)
            mnemonics = {g.mnemonic for g in hard_rep.gadgets}
            self.assertIn("pop rdi ; ret", mnemonics)
            self.assertIn("pop rsi ; ret", mnemonics)
            self.assertIn("pop rdx ; ret", mnemonics)
            self.assertIn("syscall ; ret", mnemonics)

            # 2. Unhardened binary (No PIE + No RELRO + Executable Stack + No Canary)
            weak_bin = tmp / "unhardened"
            subprocess.run(
                [
                    "gcc",
                    "-O1",
                    "-no-pie",
                    "-fno-PIE",
                    "-fno-stack-protector",
                    "-Wl,-z,norelro",
                    "-Wl,-z,execstack",
                    str(src_file),
                    "-o",
                    str(weak_bin),
                ],
                check=True,
            )
            weak_rep = audit_elf_binary(weak_bin)
            self.assertFalse(weak_rep.pie_enabled)
            self.assertFalse(weak_rep.nx_enabled)
            self.assertEqual(weak_rep.relro_mode, "No RELRO")
            self.assertFalse(weak_rep.stack_canary)
            self.assertEqual(weak_rep.aslr_leak_resistance_score, 0)

            # 3. Non-ELF file must raise ValueError
            bad_file = tmp / "not_an_elf.txt"
            bad_file.write_text("hello world")
            with self.assertRaises(ValueError):
                audit_elf_binary(bad_file)

    def test_06_cli_subcommands_and_json_export(self) -> None:
        """Verify all CLI subcommands and JSON serialization modes execute cleanly."""
        root = Path(__file__).resolve().parents[1]
        env = {"PYTHONPATH": str(root / "src"), "PATH": "/usr/bin:/bin"}

        for cmd_args in [
            ["calibrate", "-n", "300", "--json"],
            ["spectre-sim", "-t", "20", "--json"],
            ["aslr", "-s", "8", "--json"],
            ["elf-audit", "--json"],
        ]:
            out = subprocess.check_output(
                ["python3", "-m", "spectrescope.cli", *cmd_args],
                cwd=str(root),
                env=env,
                text=True,
            )
            parsed = json.loads(out)
            self.assertIsInstance(parsed, dict)

        # Also test non-JSON human-readable CLI execution
        rc = cli_main(["calibrate", "-n", "200"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
