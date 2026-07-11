#!/usr/bin/env python3
"""
signature_correlator.py

secretmem_watch.bt tarafindan uretilen ham event akisini okur, pid
bazinda bir state machine kurar ve su davranissal kalibi tespit eder:

    memfd_secret()  ->  mmap(secretmem_fd)  ->  mprotect(PROT_EXEC)  ->  [mseal()]

ONEMLI - hash'in ne oldugu konusunda net olalim:
  Bu script secretmem bolgesinin ICERIGINI (byte'larini) HICBIR ZAMAN
  okumaz/hashlemez - bu zaten teknik olarak imkansiz (kernel dahi
  okuyamiyor). Burada hashlenen sey, SADECE gorunur METADATA'dir:
    - syscall sirasi (event isimleri)
    - argumanlar (flags, len, prot)
    - adimlar arasi gecen sure (ns, kaba bir bucket'a yuvarlanmis)
  Yani bu bir "content signature" degil, bir "behavioral sequence
  fingerprint"dir. Ayni byte'lara sahip iki farkli shellcode ayni
  fingerprint'i uretebilir (polymorphism'e karsi bu YUZDEN daha
  dayanikli); ayni zamanda ayni davranis kalibini takip eden zararsiz
  bir uygulama da (yanlislikla) ayni fingerprint'i uretebilir - yani
  bu bir kesin imza degil, bir RISK SKORU / triage sinyalidir.

Kullanim:
    sudo bpftrace secretmem_watch.bt | python3 signature_correlator.py

Cikti:
    Her tam veya kismi suphelii dizi icin JSON satiri (stdout) - SIEM/
    EDR pipeline'ina kolayca beslenebilir.
"""

import sys
import json
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

# Adimlar arasi "suphelii" sayilacak maksimum sure (ns).
# Meshru kullanimda (ör. bir key'i olusturup hemen mprotect(EXEC)
# yapan bir JIT/crypto kutuphanesi) bu deger tipik olarak kisa surer;
# esik degeri ortam/gozlem ile ayarlanmali, burada demonstratif bir
# varsayilan verildi.
SUSPICIOUS_WINDOW_NS = 5_000_000_000  # 5 saniye


@dataclass
class RegionState:
    pid: int
    comm: str
    memfd_secret_ts: Optional[int] = None
    memfd_secret_flags: Optional[int] = None
    mmap_ts: Optional[int] = None
    mmap_addr: Optional[str] = None
    mmap_len: Optional[int] = None
    mmap_prot: Optional[int] = None
    mprotect_ts: Optional[int] = None
    mprotect_prot: Optional[int] = None
    mprotect_exec: bool = False
    mseal_ts: Optional[int] = None
    mseal_flags: Optional[int] = None

    def sequence_tuple(self):
        """Hash icin kullanilacak, ICERIK ICERMEYEN normalize dizi."""
        def bucket(delta):
            # Kesin ns yerine kaba bucket - kucuk jitter'lari yutar,
            # ayni zamanda "gercek ns degeri" gibi hassas bir zamanlama
            # yan-kanali da sizdirmaz.
            if delta is None:
                return None
            for edge in (1_000, 10_000, 100_000, 1_000_000, 10_000_000,
                         100_000_000, 1_000_000_000):
                if delta < edge:
                    return f"<{edge}ns"
            return ">=1s"

        d1 = (self.mmap_ts - self.memfd_secret_ts) if self.mmap_ts and self.memfd_secret_ts else None
        d2 = (self.mprotect_ts - self.mmap_ts) if self.mprotect_ts and self.mmap_ts else None
        d3 = (self.mseal_ts - self.mprotect_ts) if self.mseal_ts and self.mprotect_ts else None

        return (
            "memfd_secret", self.memfd_secret_flags,
            "mmap", self.mmap_len, self.mmap_prot,
            "mprotect", self.mprotect_prot, self.mprotect_exec,
            "mseal", self.mseal_flags is not None, self.mseal_flags,
            "delta1", bucket(d1),
            "delta2", bucket(d2),
            "delta3", bucket(d3),
        )

    def fingerprint(self) -> str:
        raw = json.dumps(self.sequence_tuple(), sort_keys=False).encode()
        return hashlib.sha256(raw).hexdigest()

    def risk_score(self) -> int:
        score = 0
        if self.memfd_secret_ts:
            score += 1
        if self.mmap_ts:
            score += 1
        if self.mprotect_exec:
            score += 3          # secretmem + PROT_EXEC gecisi = guclu sinyal
        if self.mseal_ts:
            score += 2          # + kalici hale getirme = ek sinyal
        # Hizli ardisik gecis (kucuk time-window) = daha suphelii
        if self.mmap_ts and self.memfd_secret_ts:
            if (self.mmap_ts - self.memfd_secret_ts) < SUSPICIOUS_WINDOW_NS:
                score += 1
        return score


def parse_kv(kv_str: str) -> dict:
    out = {}
    for part in kv_str.strip().split():
        if "=" in part:
            k, v = part.split("=", 1)
            out[k] = v
    return out


def main():
    regions: dict[tuple[int, str], RegionState] = {}

    for line in sys.stdin:
        line = line.strip()
        if not line.startswith("EVENT|"):
            continue
        parts = line.split("|")
        if len(parts) < 5:
            continue
        _, ev, pid_s, comm, ts_s = parts[:5]
        kv = parse_kv(parts[5]) if len(parts) > 5 else {}

        if ev in ("START", "END"):
            continue

        pid = int(pid_s) if pid_s else -1
        ts = int(ts_s) if ts_s else None

        if ev == "MEMFD_SECRET":
            key = (pid, "pending")
            st = RegionState(pid=pid, comm=comm)
            st.memfd_secret_ts = ts
            st.memfd_secret_flags = int(kv.get("flags", 0))
            regions[key] = st

        elif ev == "MMAP_SECRETMEM":
            key = (pid, "pending")
            st = regions.get(key)
            if st is None:
                st = RegionState(pid=pid, comm=comm)
            st.mmap_ts = ts
            st.mmap_addr = kv.get("addr")
            st.mmap_len = int(kv.get("len", 0))
            st.mmap_prot = int(kv.get("prot", 0))
            # Bolgeyi artik adresine gore anahtarla (birden fazla
            # bolge ayni pid'de takip edilebilsin).
            regions[(pid, st.mmap_addr)] = st
            if key in regions and key != (pid, st.mmap_addr):
                del regions[key]

        elif ev == "MPROTECT":
            addr = kv.get("addr")
            st = regions.get((pid, addr))
            if st is None:
                continue
            st.mprotect_ts = ts
            st.mprotect_prot = int(kv.get("prot", 0))
            st.mprotect_exec = kv.get("exec") == "1"
            emit_if_suspicious(st)

        elif ev == "MSEAL":
            addr = kv.get("addr")
            st = regions.get((pid, addr))
            if st is None:
                continue
            st.mseal_ts = ts
            st.mseal_flags = int(kv.get("flags", 0))
            emit_if_suspicious(st)


def emit_if_suspicious(st: RegionState):
    score = st.risk_score()
    if score < 3:
        return  # sadece memfd_secret+mmap -> henuz notable degil
    alert = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": st.pid,
        "comm": st.comm,
        "risk_score": score,
        "exec_transition": st.mprotect_exec,
        "sealed": st.mseal_ts is not None,
        "behavioral_fingerprint": st.fingerprint(),
        "note": "fingerprint is over METADATA ONLY (syscall args/sequence/"
                "timing bucket) - region contents were never read",
    }
    print(json.dumps(alert), flush=True)


if __name__ == "__main__":
    main()
