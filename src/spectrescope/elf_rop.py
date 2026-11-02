import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


# ELF64 Constants
ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1
PF_W = 0x2

DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1
DF_1_PIE = 0x8000000

# Canonical x86_64 ROP Gadget Byte Sequences
X86_64_GADGET_SIGNATURES: Dict[str, bytes] = {
    "pop rdi ; ret": b"\x5f\xc3",
    "pop rsi ; ret": b"\x5e\xc3",
    "pop rsi ; pop r15 ; ret": b"\x5e\x41\x5f\xc3",
    "pop rdx ; ret": b"\x5a\xc3",
    "pop rax ; ret": b"\x58\xc3",
    "pop rbp ; ret": b"\x5d\xc3",
    "pop rsp ; ret": b"\x5c\xc3",
    "leave ; ret": b"\xc9\xc3",
    "syscall ; ret": b"\x0f\x05\xc3",
    "syscall": b"\x0f\x05",
    "call rax": b"\xff\xd0",
    "jmp rsp": b"\xff\xe4",
    "ret (stack align)": b"\xc3",
}


@dataclass
class RopGadget:
    mnemonic: str
    vaddr: int
    raw_hex: str


@dataclass
class ElfSecurityReport:
    path: str
    arch: str
    pie_enabled: bool
    nx_enabled: bool
    relro_mode: str  # "Full RELRO", "Partial RELRO", "No RELRO"
    stack_canary: bool
    rwx_segments: int
    aslr_leak_resistance_score: int  # 0 - 100
    gadgets: List[RopGadget]
    leak_primitives: List[str]


def audit_elf_binary(binary_path: str | Path, max_gadgets_per_type: int = 3) -> ElfSecurityReport:
    path = Path(binary_path)
    data = path.read_bytes()

    if len(data) < 64 or data[:4] != ELF_MAGIC:
        raise ValueError(f"{path} is not a valid ELF binary")
    if data[4] != ELFCLASS64 or data[5] != ELFDATA2LSB:
        raise ValueError(f"{path} is not a 64-bit little-endian ELF binary")

    # Parse ELF64 Header
    (
        e_type,
        e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        _e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        _e_shentsize,
        _e_shnum,
        _e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

    arch = "x86_64" if e_machine == 0x3E else f"machine_0x{e_machine:x}"

    has_gnu_relro = False
    bind_now = False
    df_pie = False
    nx_enabled = True
    rwx_segments = 0

    exec_segments: List[tuple[int, bytes]] = []

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = (
            struct.unpack_from("<IIQQQQQQ", data, off)
        )

        if p_type == PT_GNU_STACK:
            if p_flags & PF_X:
                nx_enabled = False
        elif p_type == PT_GNU_RELRO:
            has_gnu_relro = True
        elif p_type == PT_LOAD:
            if (p_flags & PF_X) and (p_flags & PF_W):
                rwx_segments += 1
            if p_flags & PF_X:
                seg_bytes = data[p_offset : p_offset + p_filesz]
                exec_segments.append((p_vaddr, seg_bytes))
        elif p_type == PT_DYNAMIC:
            dyn_end = min(len(data), p_offset + p_filesz)
            cursor = p_offset
            while cursor + 16 <= dyn_end:
                d_tag, d_val = struct.unpack_from("<qQ", data, cursor)
                cursor += 16
                if d_tag == 0:
                    break
                if d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
                    bind_now = True
                if d_tag == DT_FLAGS_1:
                    if d_val & DF_1_NOW:
                        bind_now = True
                    if d_val & DF_1_PIE:
                        df_pie = True

    pie_enabled = (e_type == ET_DYN) and (df_pie or True)
    if has_gnu_relro and bind_now:
        relro_mode = "Full RELRO"
    elif has_gnu_relro:
        relro_mode = "Partial RELRO"
    else:
        relro_mode = "No RELRO"

    stack_canary = b"__stack_chk_fail" in data

    # Scan for potential ASLR information disclosure / GOT overwrite primitives
    candidate_symbols = [
        b"puts",
        b"printf",
        b"write",
        b"send",
        b"fwrite",
        b"gets",
        b"strcpy",
        b"read",
        b"system",
        b"execve",
    ]
    leak_primitives = [
        sym.decode("ascii") for sym in candidate_symbols if sym + b"\x00" in data
    ]

    # Scan executable PT_LOAD segments for x86_64 ROP gadgets
    found_gadgets: List[RopGadget] = []
    for mnemonic, sig in X86_64_GADGET_SIGNATURES.items():
        count = 0
        for base_vaddr, seg_bytes in exec_segments:
            search_idx = 0
            while count < max_gadgets_per_type:
                idx = seg_bytes.find(sig, search_idx)
                if idx == -1:
                    break
                found_gadgets.append(
                    RopGadget(
                        mnemonic=mnemonic,
                        vaddr=base_vaddr + idx,
                        raw_hex=sig.hex(),
                    )
                )
                count += 1
                search_idx = idx + 1
            if count >= max_gadgets_per_type:
                break

    # Compute ASLR / ROP exploitation resistance score (0-100)
    score = 0
    if pie_enabled:
        score += 35
    if nx_enabled and rwx_segments == 0:
        score += 25
    if relro_mode == "Full RELRO":
        score += 20
    elif relro_mode == "Partial RELRO":
        score += 10
    if stack_canary:
        score += 20

    return ElfSecurityReport(
        path=str(path),
        arch=arch,
        pie_enabled=pie_enabled,
        nx_enabled=nx_enabled,
        relro_mode=relro_mode,
        stack_canary=stack_canary,
        rwx_segments=rwx_segments,
        aslr_leak_resistance_score=score,
        gadgets=found_gadgets,
        leak_primitives=leak_primitives,
    )
