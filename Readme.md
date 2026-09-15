# pmtu-diag.py

**Bidirectional Path MTU diagnostics via raw ICMP, built on [scapy](https://scapy.net/).**

`pmtu-diag.py` measures the Path MTU **separately for each direction** of a link and
tells you whether PMTU Discovery actually works on the path — something a plain
`ping` cannot do. It crafts and parses packets as structured objects
(`pkt[IP].flags.MF`, `pkt[ICMP].type`, `pkt[IP].len`) rather than scraping
`ping`/`tcpdump` text, so behaviour is deterministic and identical on Linux and macOS.

Two run modes: interactive CLI use (colored, full header) and a quiet mode
for embedding behind a web frontend (`--quiet-header`) — see below.

---


## Install/Update  muxpi.sh  
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/pmtu-diag/main/e-install.sh)"
```


## What it measures

| Direction | Method |
|-----------|--------|
| **Forward** (us → target) | DF echo probes + binary search, cross-checked against the next-hop MTU reported in ICMP *Fragmentation Needed* (Type 3 / Code 4, RFC 1191). |
| **Reply** (target → us) | A non-DF request whose echo reply is large enough to force the target/return path to fragment; inbound fragments are captured at link level **before kernel reassembly**, and their IP total length is read directly. |
| **PMTUD health** | Detects whether the ICMP *Fragmentation Needed* signal is actually returned, distinguishing a working path from an ICMP-filtered black hole. |

This separation matters: a path can carry a large forward MTU while the return
path silently fragments (asymmetric MTU), and a NAT/VPN gateway can swallow the
ICMP signal entirely, causing TCP to stall instead of failing cleanly.

---

## Why link-level capture

The kernel reassembles inbound IP fragments before a normal socket (scapy's
`sr()`) ever sees them, so `sr()` reports one clean packet and hides the
fragmentation. `pmtu-diag.py` runs an `AsyncSniffer` (BPF / AF_PACKET, non-promiscuous)
to capture the raw fragments on the wire. The IP total length of the first fragment
(MF set, offset 0) is the return-path MTU at the narrowest hop.

> **Note on precision:** a fragment's first part is rounded *down* to an 8-byte
> boundary, so the captured value is a **lower bound** — the true MTU lies in
> `reply_mtu … reply_mtu + 7`.

---

## Requirements

- Python 3.8+
- [scapy](https://scapy.net/)
- Raw socket access: **root**, or a process with effective **`CAP_NET_RAW`** (Linux only).
  The script checks for this itself (`have_cap_net_raw()`, via `/proc/self/status`) and
  auto-elevates via `sudo` only if neither is present.

### Install scapy

```bash
# Debian / Ubuntu
sudo apt install python3-scapy        # or: pip install scapy

# macOS (Homebrew Python)
pip3 install scapy

# generic / PEP 668 environments
pip install scapy --break-system-packages
```

### Running without root (CAP_NET_RAW), e.g. for a web backend

For non-interactive use (cron, a web backend calling the script) you don't want
a `sudo` password prompt. Grant `CAP_NET_RAW` to a **dedicated copy** of the
Python interpreter instead — `have_cap_net_raw()` picks this up automatically
and skips the sudo re-exec.

Capabilities only work on filesystems supporting the `security.capability`
xattr (ext4/xfs/btrfs — not tmpfs/overlayfs/NFS/9p).

```bash
# 1. Locate the real interpreter binary (not a venv shim/symlink)
readlink -f "$(which python3)"

# 2. Dedicated copy — do NOT grant the capability to the system-wide python3,
#    or every script run by it could open raw sockets.
sudo cp /usr/bin/python3.11 /usr/local/bin/python3-pmtudiag

# 3. Grant the capability
sudo setcap cap_net_raw+eip /usr/local/bin/python3-pmtudiag

# 4. Verify
getcap /usr/local/bin/python3-pmtudiag
# -> /usr/local/bin/python3-pmtudiag cap_net_raw=eip

# 5. Restrict who can use it
sudo groupadd pmtudiag
sudo chown root:pmtudiag /usr/local/bin/python3-pmtudiag
sudo chmod 750 /usr/local/bin/python3-pmtudiag
sudo usermod -aG pmtudiag <user>       # re-login (or `newgrp pmtudiag`) to apply
```

Run with the dedicated interpreter instead of `python3`/`sudo`:

```bash
/usr/local/bin/python3-pmtudiag pmtu-diag.py <target-IP>
```

Troubleshooting:
- `setcap` silently not taking effect → confirm the filesystem (`df -T <path>`)
  supports xattrs; check `echo $?` after `setcap`; confirm `libcap2-bin` is installed.
- Module not found only through the copy → check `sys.path`/`sys.prefix`
  (`/usr/local/bin/python3-pmtudiag -c "import sys; print(sys.prefix, sys.path)"`);
  fix via `PYTHONPATH`/`PYTHONHOME`.
- Root but still failing → in a container, root can lack `CAP_NET_RAW` in the
  effective set even though `euid == 0`; the script detects and reports this case
  explicitly rather than silently falling back to sudo.
- The capability is tied to that exact file; re-copy and re-`setcap` after any
  interpreter upgrade/reinstall.

---

## Usage

```bash
./pmtu-diag.py <target-IP> [-i IFACE] [-c COUNT] [--max MTU] [--timeout SEC] [--quiet-header]
```

| Option | Default | Description |
|--------|---------|-------------|
| `target` | — | Destination **IP address or hostname** (required). |
| `-i`, `--iface` | scapy route lookup | Network interface to probe from. |
| `-c`, `--count` | `3` | Probes per test; a majority (`count//2 + 1`) must succeed to confirm a size. |
| `--max` | local MTU | Upper MTU bound for the forward binary search. |
| `--timeout` | `2.0` | Per-probe reply timeout in seconds. |
| `--quiet-header` | off | Suppress the banner/timestamp/interface/local-MTU/source-IP header lines. For embedding behind a web frontend (e.g. `pmtu.php`): those server-internal details aren't meaningful to a visitor, and the target is already shown on the page. The `1/5` … `5/5` section headers still print. |

The script auto-elevates with `sudo` when neither root nor `CAP_NET_RAW` is
available, so a leading `sudo` is optional interactively.

### Examples

```bash
# Probe a remote gateway over the default route
./pmtu-diag.py 192.0.2.1

# Force a specific interface and a wider search ceiling
./pmtu-diag.py 198.51.100.10 -i en0 --max 9000

# Higher confidence on a lossy/mobile link
./pmtu-diag.py 203.0.113.5 -c 5 --timeout 3

# Web-embedded call (no banner/interface/local-IP details)
./pmtu-diag.py 192.0.2.1 --quiet-header
```

---

## Output

The run is structured in five stages:

1. **Reachability** — basic ICMP echo sanity check.
2. **PMTUD function test** — small DF must pass; oversized DF should return *Fragmentation Needed*.
3. **Forward path MTU** — verified by DF binary search.
4. **Reply path MTU** — measured from captured inbound fragments.
5. **Result** — effective bidirectional PMTU, path symmetry, PMTUD verdict, and an MSS suggestion.

The final report includes a ready-to-use MSS clamp, e.g.:

```
Cisco IOS:   ip tcp adjust-mss 1452   (on the interface)
```

### PMTUD verdicts

| Verdict | Meaning |
|---------|---------|
| `WORKING` | ICMP *Fragmentation Needed* was returned — PMTUD functions. |
| `ICMP_FILTERED` | DF packets dropped silently — **black-hole risk**, clamp MSS. |
| `NOT_TRIGGERED` | No bottleneck below the search ceiling — raise `--max` to test. |
| `OFFLOAD_BYPASS` | DF appears bypassed (NIC offload / path fragmenting). |

A suspected **PMTUD black hole / NAT issue** is flagged separately when DF
packets vanish without any ICMP signal — typical of NAT, CGNAT, or VPN gateways
that fail to relay ICMP back to the host.

---

## Notes & limitations

- **IPv4 only.** ICMPv6 *Packet Too Big* is not yet handled.
- **Target must be a remote IP.** A loopback / local address is detected and
  rejected — local traffic never crosses the NIC, so raw probes see no reply.
- On **macOS/BPF** the OS rejects DF packets larger than the egress NIC MTU
  locally (`Message too long`). The script caps probes at the local MTU and
  reports such cases as a local send limit, not a path result.
- The reply-path MTU is a **lower bound** (8-byte fragment rounding, see above).
- `CAP_NET_RAW` auto-detection (`have_cap_net_raw()`) is Linux-only; on macOS
  the script always relies on `euid == 0` / `sudo`.

---

## Versioning

Current version: `VERSION` at the top of `pmtu-diag.py`. Each change bumps it
by `0.01`; the previous version is archived to `Archive/pmtu-diag-v<old-version>.py`.

---

## License / attribution

by ewald@jeitler.cc — <https://www.jeitler.guru>

> *When I wrote this code, only God and I knew how it worked.*
> *Now only God and the AI know it. And since the AI helped write it… good luck to all of us.*
