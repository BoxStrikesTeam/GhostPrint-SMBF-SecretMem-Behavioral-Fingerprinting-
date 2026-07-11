# GhostPrint-SMBF-SecretMem-Behavioral-Fingerprinting-
GhostPrint (SMBF — SecretMem Behavioral Fingerprinting)

# GhostPrint (SMBF — SecretMem Behavioral Fingerprinting)

A PoC that detects the `memfd_secret()` + `mmap()` + `mprotect()` +
`mseal()` call sequence and produces a **behavioral fingerprint**
from visible syscall metadata alone — without ever reading the
contents of the protected memory region.

## Background

`memfd_secret()` removes its backing pages from the kernel's direct
map entirely, so the region's contents are unreadable by any
in-kernel path — including eBPF's `bpf_probe_read_user()`,
`/proc/pid/mem`, and ptrace. `mseal()` can additionally lock the
mapping's protection bits so they can't be relaxed back. Neither
primitive is a bug: this is exactly memfd_secret's design goal
(protect secrets even from a compromised kernel).

Combined, though, an unprivileged process can carve out a region that
host-based EDR/eBPF tooling cannot inspect and cannot force back into
an inspectable state — a discussion raised on LKML with memfd_secret
maintainer Mike Rapoport and reviewed by Paul Moore. The conclusion
of that thread: this isn't a kernel gap to patch (there's no safe
middle ground between "kernel can never read this" and "kernel can
read this under some capability gate" — the latter just reintroduces
the read primitive memfd_secret was designed to remove). It's a
detection-engineering problem to solve on top of the syscall
interface that memfd_secret does **not** hide.

**What memfd_secret hides:** the region's contents.
**What it does *not* hide:** that the region exists, its size, its
protection-flag transitions, and the timing/sequence of the syscalls
that created and modified it. All of that is ordinary syscall
metadata, visible to any tracer with the normal privileges to attach
to the process — content-blind, but not behavior-blind.

GhostPrint / SMBF is built entirely on that second category. It
requires no kernel changes and no new BPF helper.

## Architecture

```
kernel side (bpftrace)              userspace side (python)
-----------------------             ------------------------
sys_enter_memfd_secret     \
sys_exit_memfd_secret        \
sys_enter/exit_mmap            >---> raw EVENT lines (stdout) ---> per-pid state machine
sys_enter_mprotect            /                                    + risk score
sys_enter_mseal              /                                     + SHA-256 fingerprint
```

- **Kernel side (`secretmem_watch.bt`)**: emits events only. No
  correlation, no hashing, no state. Every field it collects is
  already visible via `/proc/pid/maps` or syscall arguments —
  none of it falls under memfd_secret's confidentiality guarantee.
- **Userspace side (`signature_correlator.py`)**: builds a per-pid
  state machine, and once enough of the sequence
  `memfd_secret → mmap → mprotect(EXEC) → [mseal]` is observed within
  a time window, hashes the *sequence* (syscall names, arguments,
  coarse timing buckets) into a SHA-256 fingerprint and emits a JSON
  alert.

## Why this is not a "content hash"

Hashing memory contents requires reading them, which would violate
memfd_secret's threat model regardless of how the read path is
gated — that was the core objection raised (and accepted) in the
LKML discussion against adding any new kernel-side read primitive,
even a capability-gated one.

This tool never does that. The only thing hashed is: syscall names,
arguments (flags/len/prot), and coarse timing deltas between steps.
As a consequence, **two processes with completely different injected
byte content but the same behavioral sequence produce the same
fingerprint.** That's intentional — it's what makes this more
resilient to polymorphic/metamorphic shellcode than a classic
content-hash signature would be, at the cost of being a
behavioral/triage signal rather than a cryptographically exact match.

## Running it

```bash
sudo bpftrace secretmem_watch.bt | python3 signature_correlator.py
```

Requires root or `CAP_BPF` + `CAP_PERFMON`, a BTF-enabled kernel, and
kernel support for the relevant syscalls (`mseal()`: 6.10+).

## Testing without a live kernel

`signature_correlator.py` can be exercised with synthetic EVENT lines
on stdin:

```bash
python3 signature_correlator.py <<'EOF'
EVENT|MEMFD_SECRET|1234|proc|1000000000|flags=0 fd=5
EVENT|MMAP_SECRETMEM|1234|proc|1000500000|addr=0x7f0000000000 len=4096 prot=3
EVENT|MPROTECT|1234|proc|1000600000|addr=0x7f0000000000 len=4096 prot=5 exec=1
EVENT|MSEAL|1234|proc|1000700000|addr=0x7f0000000000 len=4096 flags=1
EOF
```

A process that only does `memfd_secret()+mmap()` without an EXEC
transition should produce no output — no false positive.

## Known limitations (please read before citing this as a complete solution)

1. **mprotect/mseal correlation relies on exact address matching.**
   If the attacker calls `mprotect()` on a different address (e.g.
   after `mremap()`), this PoC misses it. A production version would
   need range-based matching (an interval tree / `BPF_MAP_TYPE_LPM_TRIE`),
   better done in libbpf/C than bpftrace.

2. **Generic RIP-based syscall attribution is not included.** The
   idea discussed on LKML — attributing *any* syscall to a
   secretmem-backed region via `pt_regs->ip`, not just mmap/mprotect/
   mseal — was left out for portability; it can be added via
   `kprobe:do_syscall_64` + `PT_REGS_IP()` on x86_64.

3. **This is a heuristic/triage signal, not a definitive signature.**
   A benign application following a similar sequence (a JIT compiler,
   a crypto library that later mprotects a key region) can produce a
   similar risk score. Tune `risk_score` thresholds and timing
   buckets to your environment.

4. **An attacker who skips steps evades detection.** Mapping the
   region `PROT_EXEC` from the start, or never calling `mseal()`,
   shortens the sequence and lowers the score. This tool does not
   claim to catch every case — it surfaces one specific behavior
   class (opt-in confidentiality followed by making the region
   executable) more reliably than content-based scanning can.

## Provenance

This project came out of a public LKML discussion about the
`memfd_secret()` + `mseal()` interaction and its implications for
host-based introspection tooling, with Mike Rapoport (memfd_secret
author) and Paul Moore. The consensus reached there — no kernel patch
needed, this is a userspace detection problem — is what this repo
implements.
