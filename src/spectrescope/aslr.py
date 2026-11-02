import math
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass
class RegionEntropy:
    name: str
    sample_count: int
    min_addr: int
    max_addr: int
    varying_mask: int
    varying_bits_count: int
    shannon_entropy_bits: float
    page_alignment_bits: int
    assessment: str


@dataclass
class AslrAuditReport:
    kernel_randomize_va_space: int
    samples: int
    regions: Dict[str, RegionEntropy]


def _get_aslr_binary() -> Path:
    root = Path(__file__).resolve().parents[2]
    bin_path = root / "build" / "aslr_probe"
    if not bin_path.exists():
        subprocess.run(["make", "-C", str(root)], check=True)
    return bin_path


def _compute_region_entropy(name: str, addrs: List[int]) -> RegionEntropy:
    n = len(addrs)
    if n < 2:
        raise ValueError("At least 2 address samples required for entropy analysis")

    # Determine which bit positions ever flip across all samples
    and_all = addrs[0]
    or_all = addrs[0]
    for a in addrs[1:]:
        and_all &= a
        or_all |= a
    varying_mask = or_all ^ and_all

    varying_bits = [b for b in range(64) if (varying_mask >> b) & 1]
    varying_bits_count = len(varying_bits)

    # Sum per-bit binary Shannon entropy across active bit positions
    shannon_sum = 0.0
    for b in varying_bits:
        ones = sum(1 for a in addrs if (a >> b) & 1)
        p1 = ones / n
        p0 = 1.0 - p1
        if 0.0 < p1 < 1.0:
            shannon_sum += -(p1 * math.log2(p1) + p0 * math.log2(p0))

    # Count trailing constant bits (e.g., 12 bits for 4KB page alignment)
    lowest_varying = varying_bits[0] if varying_bits else 0

    if shannon_sum >= 24.0:
        assessment = "STRONG (>=24 bits: brute-force impractical without info leak)"
    elif shannon_sum >= 16.0:
        assessment = "MODERATE (16-23 bits: susceptible to partial pointer overwrite / heap spray)"
    elif shannon_sum > 0.0:
        assessment = "WEAK (<16 bits: feasible brute-force under local fork/respawn)"
    else:
        assessment = "DISABLED (0 bits: static addresses)"

    return RegionEntropy(
        name=name,
        sample_count=n,
        min_addr=min(addrs),
        max_addr=max(addrs),
        varying_mask=varying_mask,
        varying_bits_count=varying_bits_count,
        shannon_entropy_bits=round(shannon_sum, 2),
        page_alignment_bits=lowest_varying,
        assessment=assessment,
    )


def analyze_aslr_entropy(samples: int = 64) -> AslrAuditReport:
    bin_path = _get_aslr_binary()

    va_setting = -1
    va_path = Path("/proc/sys/kernel/randomize_va_space")
    if va_path.exists():
        try:
            va_setting = int(va_path.read_text().strip())
        except ValueError:
            va_setting = -1

    pie_addrs: List[int] = []
    stack_addrs: List[int] = []
    heap_addrs: List[int] = []
    mmap_addrs: List[int] = []

    for _ in range(samples):
        out = subprocess.check_output([str(bin_path)], text=True).strip()
        parts = out.split()
        pie_addrs.append(int(parts[0], 16))
        stack_addrs.append(int(parts[1], 16))
        heap_addrs.append(int(parts[2], 16))
        mmap_addrs.append(int(parts[3], 16))

    regions = {
        "PIE (.text)": _compute_region_entropy("PIE (.text)", pie_addrs),
        "Stack": _compute_region_entropy("Stack", stack_addrs),
        "Heap (brk)": _compute_region_entropy("Heap (brk)", heap_addrs),
        "mmap / Shared Libs": _compute_region_entropy("mmap / Shared Libs", mmap_addrs),
    }

    return AslrAuditReport(
        kernel_randomize_va_space=va_setting,
        samples=samples,
        regions=regions,
    )
