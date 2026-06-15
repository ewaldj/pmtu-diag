#!/usr/bin/env python3
# - - - - - - - - - - - - - - - - - - - - - - - -
# pmtu-diag.py  by ewald@jeitler.cc 2026 https://www.jeitler.guru
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only God and I knew how it worked.
# Now only God and the AI know it.
# And since the AI helped write it… good luck to all of us.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

# ================================================================
# pmtu-diag.py — bidirectional Path MTU diagnostics via raw ICMP
#
# Determines, separately for each direction:
#   * forward path MTU  (us -> target), via DF probes + binary search,
#     cross-checked against the next-hop MTU reported in ICMP
#     "fragmentation needed" (Type 3 Code 4, RFC 1191)
#   * reply  path MTU  (target -> us), by sending a non-DF request whose
#     echo reply is large enough to force the target to fragment, then
#     reading the inbound fragments' IP total length directly
#   * whether PMTU discovery actually works (is the ICMP signal returned)
#
# Built on scapy so packets are crafted and parsed as structured objects
# (pkt[IP].flags.MF, pkt[ICMP].type, pkt[IP].len) instead of by scraping
# ping/tcpdump text — deterministic and identical on Linux and macOS.
#
# Requires: Python 3.8+, scapy, and root (raw sockets).
#   Debian/Ubuntu : sudo apt install python3-scapy   (or pip install scapy)
#   macOS (brew)  : pip3 install scapy
#
# Usage: ./pmtu-diag.py <target-IP> [-i IFACE] [-c COUNT] [--max MTU]
#   (auto-elevates via sudo if not already root)
# ================================================================

VERSION = "0.92"

import argparse
import os
import sys
import time

# IPv4 / ICMP framing constants
IP_HDR = 20          # IPv4 header without options
ICMP_HDR = 8         # ICMP echo header
PROBE_OVERHEAD = IP_HDR + ICMP_HDR   # 28 bytes added to the ICMP payload
IPV4_MIN_MTU = 576   # RFC 791 minimum that every host must handle
TCP_OVERHEAD = 40    # IP(20) + TCP(20), for the MSS suggestion


# ── Hard requirement checks (abort with a clear message) ─────────
def die(msg, code=1):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(code)


try:
    # Silence scapy's own logging. It otherwise prints IPv6/route warnings
    # on import AND dumps a full traceback to stderr on send errors like
    # EMSGSIZE (which we catch and handle ourselves). CRITICAL hides those.
    import logging
    for _ln in ("scapy", "scapy.runtime", "scapy.sendrecv", "scapy.interactive"):
        logging.getLogger(_ln).setLevel(logging.CRITICAL)
    from scapy.all import IP, ICMP, Raw, sr1, sr, send, AsyncSniffer, conf
except ImportError:
    die(
        "ERROR: scapy is not installed.\n"
        "  Debian/Ubuntu : sudo apt install python3-scapy\n"
        "  macOS (brew)  : pip3 install scapy\n"
        "  generic       : pip install scapy --break-system-packages"
    )

if os.geteuid() != 0:
    # Not running as root. Re-exec the script through sudo so the user is
    # prompted for their password, then continues as root. We guard against
    # an infinite loop with an env marker in case sudo itself fails to
    # elevate (e.g. user not in sudoers).
    if os.environ.get("PMTU_DIAG_SUDO_REEXEC") == "1":
        die("ERROR: still not root after sudo — cannot acquire raw sockets.\n"
            "  Run the script directly as root instead.")
    sudo_path = None
    for p in ("/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"):
        if os.path.exists(p):
            sudo_path = p
            break
    if sudo_path is None:
        die("ERROR: root privileges are required (raw sockets) and 'sudo'\n"
            "  was not found. Re-run as root: " + " ".join(sys.argv))
    sys.stderr.write("Root privileges required — elevating via sudo...\n")
    env = dict(os.environ, PMTU_DIAG_SUDO_REEXEC="1")
    # Re-exec through sudo. We pass the absolute interpreter path
    # (sys.executable) explicitly, so the same Python (e.g. Homebrew with
    # scapy installed) is used as root without relying on env passing.
    argv = [sudo_path, sys.executable] + [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    try:
        os.execvpe(sudo_path, argv, env)
    except Exception as e:
        die("ERROR: failed to re-exec via sudo: %s" % e)
    # execvpe replaces this process; reaching here means it failed.
    die("ERROR: sudo elevation did not take effect.")



# ── Colors (only when stdout is a TTY) ───────────────────────────
class C:
    if sys.stdout.isatty():
        RED = "\033[0;31m"; GRN = "\033[0;32m"; YLW = "\033[1;33m"
        CYN = "\033[0;36m"; BLD = "\033[1m";    RST = "\033[0m"
        GRY = "\033[2;37m"; MGN = "\033[0;35m"
    else:
        RED = GRN = YLW = CYN = BLD = RST = GRY = MGN = ""


def hdr(title):
    pad = max(0, 56 - len(title))
    print("\n%s%s── %s %s%s%s" % (C.BLD, C.MGN, title, C.RST, C.GRY, "-" * pad) + C.RST)


def ok(msg):   print("  %sOK%s   %s" % (C.GRN, C.RST, msg))
def fail(msg): print("  %sXX%s   %s" % (C.RED, C.RST, msg))
def warn(msg): print("  %s!!%s   %s" % (C.YLW, C.RST, msg))
def info(msg): print("  %s->%s   %s" % (C.GRY, C.RST, msg))
def row(label, val, color=""):
    print("  %-42s %s%s%s%s" % (label, color, C.BLD, val, C.RST))


# ── Low-level probe primitives ───────────────────────────────────
# A "probe" is a single ICMP echo request of a chosen total IP size.
# total_size = payload + 28; payload is what scapy puts in Raw().

def make_request(target, total_size, df, ident, seq):
    """Build an ICMP echo probe of a given total IP size."""
    flags = "DF" if df else 0
    payload_len = max(0, total_size - PROBE_OVERHEAD)
    pkt = IP(dst=target, flags=flags) / \
        ICMP(type=8, id=ident, seq=seq) / (b"\xa5" * payload_len)
    return pkt


def classify_reply(reply):
    """Return (kind, nexthop_mtu).
    kind: 'echo' (echo reply received),
          'frag-needed' (Type 3 Code 4 from a bottleneck — RFC 1191),
          'other', or None (no reply)."""
    if reply is None:
        return (None, 0)
    if not reply.haslayer(ICMP):
        return ("other", 0)
    icmp = reply[ICMP]
    if icmp.type == 0:                      # echo reply
        return ("echo", 0)
    if icmp.type == 3 and icmp.code == 4:   # fragmentation needed (RFC 1191)
        nh = int(getattr(icmp, "nexthopmtu", 0) or 0)
        return ("frag-needed", nh)
    return ("other", 0)


def probe_df(target, total_size, iface, timeout, ident):
    """Send a single DF echo of total_size. Returns (status, nexthop_mtu).
    status: 'pass' | 'frag-needed' | 'timeout' | 'other' | 'local-reject'.
    'pass' = echo reply. 'local-reject' = the OS refused to send locally
    (packet > egress NIC MTU; common on macOS/BPF — never left the host)."""
    pkt = make_request(target, total_size, df=True, ident=ident,
                       seq=total_size & 0xffff)
    try:
        reply = sr1(pkt, timeout=timeout, verbose=0)
    except OSError:
        return ("local-reject", 0)
    except Exception:
        return ("local-reject", 0)
    kind, nh = classify_reply(reply)
    if kind == "echo":
        return ("pass", 0)
    if kind == "frag-needed":
        return ("frag-needed", nh)
    if kind is None:
        return ("timeout", 0)
    return ("other", 0)


def probe_df_repeat(target, total_size, iface, timeout, ident, count, need):
    """Repeat a DF probe up to `count` times; 'pass' if >= need confirmations.
    Returns ('pass'|'fail'|'frag-needed'|'local-reject', nexthop_mtu_seen)."""
    confirms = 0
    nh_seen = 0
    saw_frag = False
    saw_reject = False
    for i in range(count):
        status, nh = probe_df(target, total_size, iface, timeout, ident + i)
        if status == "pass":
            confirms += 1
        elif status == "frag-needed":
            saw_frag = True
            if nh:
                nh_seen = nh
        elif status == "local-reject":
            saw_reject = True
    if confirms >= need:
        return ("pass", nh_seen)
    if saw_frag:
        return ("frag-needed", nh_seen)
    if saw_reject and confirms == 0:
        return ("local-reject", nh_seen)
    return ("fail", nh_seen)


# ── Reply-path measurement (target -> us) ────────────────────────
# We send NON-DF echo requests big enough that the reply must come back
# in fragments if ANY MTU on the return path (target egress OR a path
# bottleneck) is smaller than the reply. The catch: the kernel reassembles
# incoming fragments before a normal socket (scapy's sr()) ever sees them,
# so sr() reports a single clean packet and hides the fragmentation. To see
# the wire truth we run an AsyncSniffer at link level (BPF/AF_PACKET), which
# captures the raw fragments BEFORE the kernel reassembles them. The IP
# total length of the first fragment (MF set, offset 0) is the return-path
# MTU at the narrowest hop.

def measure_reply_mtu(target, total_size, iface, timeout, ident, count):
    """Returns (frag_count, reply_mtu, sent_ok, sniffer_ok).
    reply_mtu = IP total length of the largest first/middle fragment seen
    (0 = no fragmentation observed). sent_ok=False means the probe could
    not be sent locally (packet > egress NIC MTU; macOS/BPF EMSGSIZE).
    sniffer_ok=False means the link-level capture never started (no capture
    privilege / bad iface) — a 0 result is then inconclusive, not a path fact."""
    frag_total = 0
    reply_mtu = 0
    sent_ok = False
    sniffer_ok = False

    # BPF filter: inbound IP fragments from target. (ip[6:2] & 0x3fff) != 0
    # matches first fragment (MF set) and following fragments (offset > 0),
    # while ignoring the DF bit (0x4000). We do NOT restrict to icmp because
    # trailing fragments carry no ICMP header and would be missed.
    bpf = "src host %s and (ip[6:2] & 0x3fff) != 0" % target
    try:
        sniffer = AsyncSniffer(filter=bpf, iface=iface, store=True)
        sniffer.start()
        sniffer_ok = True
    except Exception:
        # Sniffer could not start (no capture privilege / bad iface).
        sniffer = None

    import time as _t
    for i in range(count):
        pkt = make_request(target, total_size, df=False, ident=ident + i, seq=i + 1)
        try:
            send(pkt, verbose=0)
            sent_ok = True
        except OSError:
            continue          # EMSGSIZE — packet exceeds local NIC MTU
        except Exception:
            continue
        _t.sleep(max(0.2, timeout / 3.0))   # let the reply (+fragments) arrive

    captured = []
    if sniffer is not None:
        # Wait a full timeout span after the last send so late fragments on a
        # high-latency path (WAN / mobile) are still captured before stop.
        _t.sleep(max(0.5, timeout))
        try:
            captured = sniffer.stop() or []
        except Exception:
            captured = []

    for recv in captured:
        if not recv.haslayer(IP):
            continue
        ip = recv[IP]
        if ip.src != target:
            continue
        mf = bool(int(ip.flags) & 0x1)    # More Fragments
        offset = ip.frag                   # in 8-byte units
        if mf or offset > 0:
            frag_total += 1
            if mf and ip.len > reply_mtu:
                reply_mtu = ip.len
    # NOTE: the exact MTU is NOT uniquely recoverable from a fragment. The
    # first fragment's data is rounded DOWN to an 8-byte boundary, so an MTU
    # of 1469..1475 all yield ip.len 1468. We therefore report the captured
    # value as a lower bound (the true MTU is reply_mtu .. reply_mtu+7).
    return (frag_total, reply_mtu, sent_ok, sniffer_ok)


# ── Local interface MTU ──────────────────────────────────────────
def local_mtu_for(iface):
    """Best-effort local MTU lookup, portable across Linux and macOS."""
    try:
        if sys.platform.startswith("linux"):
            with open("/sys/class/net/%s/mtu" % iface) as f:
                return int(f.read().strip())
        else:
            import subprocess
            out = subprocess.check_output(["ifconfig", iface],
                                          stderr=subprocess.DEVNULL).decode()
            # parse "mtu 1500"
            parts = out.split()
            if "mtu" in parts:
                return int(parts[parts.index("mtu") + 1])
    except Exception:
        pass
    return 1500


# ── Forward binary search ────────────────────────────────────────
def binary_search_mtu(target, iface, timeout, count, need, lo_start, hi_start,
                      ident_base, verbose=True):
    """Run a DF binary search for the forward path MTU.
    Returns a dict with keys: mtu, iterations, saw_fragneeded, saw_silent,
    nexthop. Prints each probe when verbose."""
    lo, hi = lo_start, hi_start + 1
    iterations = 0
    nexthop = 0
    saw_frag = False
    saw_silent = False
    while hi - lo > 1:
        mid = (lo + hi) // 2
        iterations += 1
        status, nh = probe_df_repeat(target, mid, iface, timeout,
                                     ident=ident_base + iterations * count,
                                     count=count, need=need)
        if nh:
            nexthop = nh
        if status == "pass":
            tag = "%sOK%s" % (C.GRN, C.RST)
            lo = mid
        elif status == "frag-needed":
            tag = "%sDROP (frag-needed)%s" % (C.RED, C.RST)
            saw_frag = True
            hi = mid
        elif status == "local-reject":
            tag = "%sn/a (local NIC limit)%s" % (C.YLW, C.RST)
            hi = mid
        else:
            tag = "%sDROP (silent)%s" % (C.RED, C.RST)
            saw_silent = True
            hi = mid
        if verbose:
            print("  Test %2d:  MTU %4d B  (payload %4d B)  —  %s" %
                  (iterations, mid, mid - PROBE_OVERHEAD, tag))
    return {"mtu": lo, "iterations": iterations, "saw_fragneeded": saw_frag,
            "saw_silent": saw_silent, "nexthop": nexthop}


def pmtud_verdict(saw_frag, saw_silent, pending):
    if saw_frag:
        return "WORKING"
    if saw_silent:
        return "ICMP_FILTERED"
    if pending:
        return "NOT_TRIGGERED"
    return "UNKNOWN"


# ── Main ─────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Bidirectional Path MTU diagnostics via raw ICMP (scapy).")
    ap.add_argument("target", help="destination IP address or hostname")
    ap.add_argument("-i", "--iface", default=None,
                    help="network interface (default: scapy route lookup)")
    ap.add_argument("-c", "--count", type=int, default=3,
                    help="probes per test (default: 3)")
    ap.add_argument("--max", type=int, default=None,
                    help="upper MTU bound for the search (default: local MTU)")
    ap.add_argument("--timeout", type=float, default=2.0,
                    help="per-probe reply timeout in seconds (default: 2)")
    args = ap.parse_args()

    target = args.target
    target_host = None
    # Resolve a hostname to an IPv4 address. scapy's routing and our BPF
    # filters need a literal IP; an unresolved name would fail downstream.
    try:
        import ipaddress as _ipa
        _ipa.ip_address(target)          # already a literal IP -> no lookup
    except ValueError:
        import socket
        try:
            resolved = socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]
            target_host = target
            target = resolved
        except Exception:
            die("ERROR: could not resolve hostname '%s' to an IPv4 address." % target)

    # Resolve interface and source via scapy's routing table if not given.
    try:
        route_iface, src_ip, _gw = conf.route.route(target)
    except Exception:
        route_iface, src_ip = (None, None)
    iface = args.iface or route_iface
    count = max(1, args.count)
    need = (count // 2) + 1     # majority of probes must succeed
    timeout = args.timeout

    # Bind scapy's send/receive to the resolved interface globally. On L3
    # sockets the per-call iface= argument is ignored (scapy warns), so the
    # correct knob is conf.iface. Without this, captures may listen on the
    # wrong NIC and replies are missed.
    if iface:
        try:
            conf.iface = iface
        except Exception:
            pass

    # Detect a loopback target (the target IS one of our own addresses).
    # Such traffic never traverses the wire NIC, so raw L3 probing on a
    # physical interface will not see the reply. Warn early and clearly.
    is_loopback_target = False
    try:
        if src_ip and src_ip == target:
            is_loopback_target = True
    except Exception:
        pass

    local_mtu = local_mtu_for(iface) if iface else 1500
    max_mtu = args.max or local_mtu

    print("%s%s  ----------------------------------------------------------" % (C.BLD, C.CYN))
    print("%s%s  Path MTU Diagnostic / pmtu-diag.py v%s %s" % (C.BLD, C.CYN, VERSION, C.RST))
    print("%s%s  by AI & ewald@jeitler.cc - bidirectional, scapy-based" % (C.BLD, C.CYN))
    print("%s%s  ----------------------------------------------------------" % (C.BLD, C.CYN))
    print("  %s%s  |  Platform: %s%s" %
          (C.GRY, time.strftime("%Y-%m-%d %H:%M:%S"), sys.platform, C.RST))
    target_disp = ("%s (%s)" % (target_host, target)) if target_host else target
    print("  Target: %s%s%s   Iface: %s%s%s   Probes/test: %s%d%s" %
          (C.BLD, target_disp, C.RST, C.BLD, iface or "?", C.RST, C.BLD, count, C.RST))

    if is_loopback_target:
        warn("Target %s is one of THIS host's own addresses (loopback path)." % target)
        info("MTU probing only makes sense towards a REMOTE host. Local traffic")
        info("never crosses the NIC, so raw probes see no reply. Pick a remote IP.")
        sys.exit(2)

    # ── 1: Reachability ──────────────────────────────────────────
    hdr("1/5  Reachability")
    r = sr1(IP(dst=target) / ICMP() / (b"\xa5" * 56),
            timeout=timeout, verbose=0)
    if classify_reply(r)[0] != "echo":
        fail("Target %s did not answer a basic ICMP echo — aborting." % target)
        info("If the host replies to system ping but not here, a firewall may be")
        info("dropping crafted/raw ICMP, or the target is on a non-routed path.")
        sys.exit(1)
    ok("Reachable (basic ICMP echo answered)")
    if iface:
        ok("Interface: %s%s%s  |  local MTU: %s%d%s bytes" %
           (C.BLD, iface, C.RST, C.BLD, local_mtu, C.RST))
    if src_ip:
        info("Source IP: %s" % src_ip)

    # ── 2: PMTUD function test (does the ICMP signal come back?) ──
    hdr("2/5  PMTUD function test")
    pmtud_status = "UNKNOWN"
    nexthop_reported = 0

    # Small DF packet must pass.
    st, _ = probe_df(target, IPV4_MIN_MTU, iface, timeout, ident=0x1000)
    if st == "pass":
        ok("DF small (%dB): %spassed%s" % (IPV4_MIN_MTU, C.GRN, C.RST))
    else:
        warn("DF small (%dB): %s%s%s" % (IPV4_MIN_MTU, C.YLW, st, C.RST))

    # Oversized DF packet. NOTE: it must still FIT the local NIC, otherwise
    # the OS rejects it locally before it ever reaches the path (this is the
    # macOS/BPF "Message too long" case). So we cap the probe at the local
    # MTU and add a margin only if there is headroom. If even local_mtu is
    # the ceiling, we rely on the binary search below to surface frag-needed.
    if max_mtu < local_mtu:
        over = min(local_mtu, max_mtu + 200)
    else:
        over = local_mtu     # cannot exceed the NIC; search will reveal PMTUD
    st, nh = probe_df(target, over, iface, timeout, ident=0x2000)
    if st == "frag-needed":
        nexthop_reported = nh
        if nh:
            ok("DF oversized (%dB): %sICMP frag-needed%s, next-hop MTU = %s%d%s" %
               (over, C.GRN, C.RST, C.BLD, nh, C.RST))
        else:
            ok("DF oversized (%dB): %sICMP frag-needed%s (no next-hop MTU field)" %
               (over, C.GRN, C.RST))
        pmtud_status = "WORKING"
    elif st == "pass":
        info("DF oversized (%dB): passed — no bottleneck at/below local MTU yet" % over)
        pmtud_status = "PENDING"     # decided by the binary search
    elif st == "local-reject":
        info("DF oversized (%dB): not sendable on this NIC (local MTU %d)" % (over, local_mtu))
        info("PMTUD will be judged from the binary search (frag-needed signal).")
        pmtud_status = "PENDING"
    elif st == "timeout":
        info("DF oversized (%dB): no reply yet — deferring to binary search" % over)
        pmtud_status = "PENDING"
    else:
        info("DF oversized (%dB): %s — deferring to binary search" % (over, st))
        pmtud_status = "PENDING"

    # ── 3: Forward MTU — binary search (verified) ────────────────
    hdr("3/5  Forward path MTU (binary search)")
    info("Search range: %d - %d bytes  |  pass threshold: %d/%d" %
         (IPV4_MIN_MTU, max_mtu, need, count))
    print("")

    res = binary_search_mtu(target, iface, timeout, count, need,
                            IPV4_MIN_MTU, max_mtu, ident_base=0x3000)
    fwd_mtu = res["mtu"]
    iterations = res["iterations"]
    nexthop_during_search = res["nexthop"]

    # Final PMTUD verdict: a frag-needed in the search proves PMTUD works.
    # Silent drops without any ICMP signal = black-hole risk.
    pending = (pmtud_status == "PENDING")
    pmtud_status = pmtud_verdict(res["saw_fragneeded"], res["saw_silent"], pending)

    # ── 4: Reply MTU — capture inbound fragments (target -> us) ───
    hdr("4/5  Reply path MTU (target -> us)")
    # Use a request whose reply is as large as the LOCAL NIC allows, so a
    # smaller target egress MTU is forced to fragment. Sending larger than
    # the local MTU is pointless (the OS rejects it before it leaves the
    # host), so cap the probe at local_mtu regardless of --max.
    reply_probe_size = min(max_mtu, local_mtu)
    frag_count, reply_mtu, reply_sent_ok, reply_sniffer_ok = measure_reply_mtu(
        target, reply_probe_size, iface, timeout, ident=0x4000, count=count)

    reply_frag = False
    if not reply_sniffer_ok:
        warn("Link-level capture could not start (no capture privilege or bad iface)")
        info("Reply-path fragmentation cannot be measured without the sniffer.")
        info("A '0 fragments' result here is INCONCLUSIVE, not a path result.")
    elif not reply_sent_ok:
        warn("Reply probe (%dB) could not be sent on this NIC (local MTU %d)" %
             (reply_probe_size, local_mtu))
        info("Reply-path fragmentation could not be measured. This is a local")
        info("send limit (macOS/BPF), not a path result.")
    elif frag_count > 0 and reply_mtu > 0:
        reply_frag = True
        warn("Reply fragmented: return MTU = %s%d-%d%s bytes (%d fragment(s))" %
             (C.YLW, reply_mtu, reply_mtu + 7, C.RST, frag_count))
        info("The reply came back FRAGMENTED on the wire — a hop on the RETURN")
        info("path (target egress or a bottleneck) is smaller than the reply.")
        info("Captured pre-reassembly via link-level sniff; a plain ping hides this.")
    elif frag_count > 0:
        warn("Inbound fragments seen (%d) but could not size them — treating as fuzzy" %
             frag_count)
    else:
        ok("No reply fragmentation captured at %d bytes" % reply_probe_size)
        if reply_probe_size <= fwd_mtu:
            info("Note: reply probe (%d) was not larger than the forward MTU (%d)," %
                 (reply_probe_size, fwd_mtu))
            info("so a return-path bottleneck at/above %d could not be exercised." % fwd_mtu)
        else:
            info("Return path carried the full reply size — no smaller hop detected")

    # ── 5: Result ────────────────────────────────────────────────
    hdr("5/5  Result")
    print("")

    # Effective bidirectional MTU and MSS from the smaller direction.
    eff_mtu = fwd_mtu
    if reply_frag and 0 < reply_mtu < eff_mtu:
        eff_mtu = reply_mtu
    mss = eff_mtu - TCP_OVERHEAD

    row("Forward path MTU (verified):", "%d bytes" % fwd_mtu)
    if nexthop_reported or nexthop_during_search:
        nh = nexthop_reported or nexthop_during_search
        col = C.GRN if nh == fwd_mtu else C.YLW
        row("Forward MTU (ICMP next-hop report):", "%d bytes" % nh, col)
        if nh != fwd_mtu:
            info("Note: ICMP-reported next-hop MTU (%d) differs from the verified" % nh)
            info("value (%d). The verified binary-search result is authoritative." % fwd_mtu)
    if reply_frag:
        row("Reply path MTU (captured):", "%d bytes" % reply_mtu, C.YLW)
        row("Effective PMTU (min of both):", "%d bytes" % eff_mtu, C.YLW)

    pmtud_txt = {
        "WORKING":        "%sworking%s (ICMP frag-needed returned)" % (C.GRN, C.RST),
        "ICMP_FILTERED":  "%sICMP filtered%s -> black-hole risk" % (C.YLW, C.RST),
        "OFFLOAD_BYPASS": "%sDF bypassed%s (offload/path fragmenting)" % (C.YLW, C.RST),
        "NOT_TRIGGERED":  "%snot triggered%s (no bottleneck below %d B to test)" %
                          (C.GRY, C.RST, max_mtu),
        "PENDING":        "%sinconclusive%s" % (C.GRY, C.RST),
        "UNKNOWN":        "%sunknown%s" % (C.GRY, C.RST),
    }.get(pmtud_status, "%s%s%s" % (C.GRY, pmtud_status, C.RST))
    print("  %-42s %s" % ("PMTUD status:", pmtud_txt))

    if reply_frag and abs(reply_mtu - fwd_mtu) <= 7:
        # Within the 8-byte fragment-rounding uncertainty -> same MTU.
        print("  %-42s %ssymmetric%s (forward %d / reply ~%d)" %
              ("Path symmetry:", C.GRN, C.RST, fwd_mtu, reply_mtu))
    elif reply_frag:
        print("  %-42s %sasymmetric%s (forward %d / reply %d)" %
              ("Path symmetry:", C.YLW, C.RST, fwd_mtu, reply_mtu))
    elif not reply_sent_ok:
        print("  %-42s %sreply not measurable%s (local send limit)" %
              ("Path symmetry:", C.GRY, C.RST))
    elif reply_probe_size <= fwd_mtu:
        print("  %-42s %sreply not exercised%s (probe <= forward MTU)" %
              ("Path symmetry:", C.GRY, C.RST))
    else:
        print("  %-42s %sasymmetric%s (forward %d / reply >=%d)" %
              ("Path symmetry:", C.YLW, C.RST, fwd_mtu, reply_probe_size))
        info("Forward path is limited to %d but the reply path carries >=%d." %
             (fwd_mtu, reply_probe_size))
    row("Iterations:", "%d" % iterations)
    print("")

    # ── NAT / PMTUD black-hole detection ─────────────────────────
    # Two situations point to a hidden bottleneck that PMTU discovery does
    # NOT signal back to this host — typically a NAT/overlay (e.g. VMware
    # NAT, CGNAT, a VPN gateway) that fails to relay ICMP frag-needed:
    #
    #  (A) Forward search hit no bottleneck (fwd == local MTU) and PMTUD was
    #      never triggered, BUT the reply direction came back fragmented at
    #      a size SMALLER than our local MTU → a real bottleneck exists that
    #      the forward path never told us about.
    #  (B) Drops happened during the search but never with an ICMP signal
    #      (saw_silent) → classic black hole.
    # A real black hole means DF packets vanish WITHOUT an ICMP signal.
    # Reply-path fragmentation on its own is NOT a black hole — it is a
    # normal asymmetric MTU (a smaller receiver/return hop that fragments
    # correctly). That case is reported under "Path symmetry", not here.
    blackhole = False
    if res["saw_silent"] and not res["saw_fragneeded"]:
        blackhole = True
        reason = "DF packets were dropped silently (no ICMP frag-needed)"

    # Heuristic NAT hint from the source address (RFC 1918 / CGNAT ranges
    # behind which a NAT box commonly mangles PMTUD).
    nat_hint = False
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(src_ip or "0.0.0.0")
        nat_hint = (ip_obj.is_private or
                    ip_obj in ipaddress.ip_network("100.64.0.0/10"))  # CGNAT
    except Exception:
        nat_hint = False

    if blackhole:
        print("")
        warn("%sPMTUD BLACK-HOLE / NAT ISSUE SUSPECTED%s" % (C.RED, C.RST))
        info(reason)
        info("A device on the path (often a NAT or VPN gateway) is not")
        info("relaying ICMP 'fragmentation needed' back to this host. Large")
        info("DF packets can be silently lost — TCP stalls, not clean errors.")
        if nat_hint:
            info("Your source %s looks NAT'd, which fits this pattern (e.g." % src_ip)
            info("VMware NAT, CGNAT). Test from the HOST or in bridged mode to")
            info("compare, or clamp MSS / lower the interface MTU as a fix.")
        info("Recommended: set a fixed MSS clamp; do NOT rely on PMTUD here.")
    elif pmtud_status == "NOT_TRIGGERED":
        print("")
        info("Note: no bottleneck below %d was found, so PMTUD was not" % max_mtu)
        info("exercised. If you expect a smaller path MTU, raise --max or test")
        info("toward a target across the narrower link.")

    # ── MSS suggestion ───────────────────────────────────────────
    print("  %sMSS suggestion%s" % (C.BLD, C.RST))
    print("  %s%s%s" % (C.GRY, "-" * 52, C.RST))
    label = ("TCP MSS (effective %d - 40):" % eff_mtu) if reply_frag \
        else ("TCP MSS (%d - 40):" % eff_mtu)
    if mss < 536:
        row(label, "%d bytes" % mss, C.RED)
        warn("MSS below the TCP/IPv4 minimum (536B) — check path/measurement")
    else:
        row(label, "%d bytes" % mss, C.GRN)
    print("")
    info("Cisco IOS:   %sip tcp adjust-mss %d%s   (on the interface)" % (C.BLD, mss, C.RST))
    if reply_frag:
        info("MSS is taken from the smaller (reply) direction. The forward path alone")
        info("would allow %d - 40 = %d B, but the return path caps it." %
             (fwd_mtu, fwd_mtu - TCP_OVERHEAD))
    if pmtud_status == "ICMP_FILTERED":
        warn("PMTUD not reliable — set a fixed MSS clamp, do not rely on PMTUD")
    elif pmtud_status == "NOT_TRIGGERED":
        info("PMTUD could not be exercised (no bottleneck in range). Raise --max")
        info("or test toward a path with a known smaller MTU to verify it.")
    print("")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)