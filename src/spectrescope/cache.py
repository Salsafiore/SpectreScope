import ctypes
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List


class _CacheCalibrationResult(ctypes.Structure):
    _fields_ = [
        ("hit_mean_cycles", ctypes.c_uint64),
        ("hit_median_cycles", ctypes.c_uint64),
        ("hit_p90_cycles", ctypes.c_uint64),
        ("miss_mean_cycles", ctypes.c_uint64),
        ("miss_median_cycles", ctypes.c_uint64),
        ("miss_p10_cycles", ctypes.c_uint64),
        ("threshold_cycles", ctypes.c_uint64),
        ("separability_ratio", ctypes.c_double),
        ("sample_count", ctypes.c_uint32),
    ]


class _SpectreByteResult(ctypes.Structure):
    _fields_ = [
        ("recovered_byte", ctypes.c_uint8),
        ("runner_up_byte", ctypes.c_uint8),
        ("best_hits", ctypes.c_uint32),
        ("runner_up_hits", ctypes.c_uint32),
        ("total_trials", ctypes.c_uint32),
        ("best_avg_cycles", ctypes.c_uint64),
        ("confidence", ctypes.c_double),
    ]


@dataclass
class CacheProfile:
    hit_mean_cycles: int
    hit_median_cycles: int
    hit_p90_cycles: int
    miss_mean_cycles: int
    miss_median_cycles: int
    miss_p10_cycles: int
    threshold_cycles: int
    separability_ratio: float
    sample_count: int
    hit_samples: List[int]
    miss_samples: List[int]


@dataclass
class SpectreReadByte:
    offset: int
    expected_char: str
    recovered_char: str
    recovered_byte: int
    best_hits: int
    runner_up_hits: int
    total_trials: int
    best_avg_cycles: int
    confidence: float


@dataclass
class SpectreLeakReport:
    target_secret: str
    recovered_secret: str
    accuracy: float
    threshold_cycles: int
    array1_base: int
    secret_base: int
    oob_delta: int
    byte_results: List[SpectreReadByte]


def _get_project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_native_lib() -> ctypes.CDLL:
    root = _get_project_root()
    lib_path = root / "build" / "libspectrescope.so"
    if not lib_path.exists():
        subprocess.run(["make", "-C", str(root)], check=True)
    lib = ctypes.CDLL(str(lib_path))

    lib.calibrate_cache_latency.argtypes = [
        ctypes.c_uint32,
        ctypes.POINTER(_CacheCalibrationResult),
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.POINTER(ctypes.c_uint64),
    ]
    lib.calibrate_cache_latency.restype = ctypes.c_int

    lib.spectre_v1_recover_secret.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(_SpectreByteResult),
    ]
    lib.spectre_v1_recover_secret.restype = ctypes.c_int

    lib.spectre_v1_get_target_secret.argtypes = [ctypes.POINTER(ctypes.c_size_t)]
    lib.spectre_v1_get_target_secret.restype = ctypes.c_char_p

    lib.spectre_v1_get_array1_base.argtypes = []
    lib.spectre_v1_get_array1_base.restype = ctypes.c_uint64

    lib.spectre_v1_get_secret_base.argtypes = []
    lib.spectre_v1_get_secret_base.restype = ctypes.c_uint64

    return lib


def run_cache_calibration(iterations: int = 2000) -> CacheProfile:
    lib = load_native_lib()
    res = _CacheCalibrationResult()
    hit_arr = (ctypes.c_uint64 * iterations)()
    miss_arr = (ctypes.c_uint64 * iterations)()

    rc = lib.calibrate_cache_latency(iterations, ctypes.byref(res), hit_arr, miss_arr)
    if rc != 0:
        raise RuntimeError(f"Native cache calibration failed with code {rc}")

    return CacheProfile(
        hit_mean_cycles=res.hit_mean_cycles,
        hit_median_cycles=res.hit_median_cycles,
        hit_p90_cycles=res.hit_p90_cycles,
        miss_mean_cycles=res.miss_mean_cycles,
        miss_median_cycles=res.miss_median_cycles,
        miss_p10_cycles=res.miss_p10_cycles,
        threshold_cycles=res.threshold_cycles,
        separability_ratio=res.separability_ratio,
        sample_count=res.sample_count,
        hit_samples=[int(hit_arr[i]) for i in range(iterations)],
        miss_samples=[int(miss_arr[i]) for i in range(iterations)],
    )


def run_spectre_v1_simulation(
    trials_per_byte: int = 40,
    threshold_cycles: int | None = None,
) -> SpectreLeakReport:
    lib = load_native_lib()
    if threshold_cycles is None:
        cal = run_cache_calibration(1000)
        threshold_cycles = cal.threshold_cycles

    secret_len = ctypes.c_size_t(0)
    target_bytes = lib.spectre_v1_get_target_secret(ctypes.byref(secret_len))
    target_str = target_bytes.decode("utf-8", errors="replace")
    n = secret_len.value

    out_buf = ctypes.create_string_buffer(n + 1)
    byte_res_arr = (_SpectreByteResult * n)()

    rc = lib.spectre_v1_recover_secret(
        trials_per_byte,
        threshold_cycles,
        out_buf,
        n + 1,
        byte_res_arr,
    )
    if rc < 0:
        raise RuntimeError(f"Spectre v1 simulation failed with code {rc}")

    recovered_str = out_buf.value.decode("latin-1", errors="replace")
    byte_reports: List[SpectreReadByte] = []
    matches = 0
    for i in range(n):
        b = byte_res_arr[i]
        ch = chr(b.recovered_byte) if 32 <= b.recovered_byte <= 126 else "?"
        exp_ch = target_str[i]
        if ch == exp_ch:
            matches += 1
        byte_reports.append(
            SpectreReadByte(
                offset=i,
                expected_char=exp_ch,
                recovered_char=ch,
                recovered_byte=int(b.recovered_byte),
                best_hits=int(b.best_hits),
                runner_up_hits=int(b.runner_up_hits),
                total_trials=int(b.total_trials),
                best_avg_cycles=int(b.best_avg_cycles),
                confidence=float(b.confidence),
            )
        )

    arr1_base = int(lib.spectre_v1_get_array1_base())
    sec_base = int(lib.spectre_v1_get_secret_base())

    return SpectreLeakReport(
        target_secret=target_str,
        recovered_secret=recovered_str,
        accuracy=(matches / n) if n > 0 else 1.0,
        threshold_cycles=threshold_cycles,
        array1_base=arr1_base,
        secret_base=sec_base,
        oob_delta=sec_base - arr1_base,
        byte_results=byte_reports,
    )
