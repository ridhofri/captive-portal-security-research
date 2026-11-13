#!/usr/bin/env python3
"""
evil_twin_detector.py  —  defensive rogue-AP / evil-twin detector
==================================================================

A BLUE-TEAM tool. It scans the Wi-Fi environment and flags access points
that show the signatures of an evil twin. It does NOT attack, inject, or
connect to anything — it only reads nearby beacon information.

Signals it looks for
--------------------
  1. SSID / BSSID conflict : one SSID broadcast by several MAC addresses
                             (legitimate for enterprise mesh, suspicious for
                             a home/cafe SSID — compare against a baseline).
  2. Encryption downgrade  : the same SSID offered both secured AND open,
                             or weaker than its known profile — the classic
                             "free wifi" lure.                     [HIGH]
  3. Baseline deviation    : a BSSID broadcasting a trusted SSID that was
                             NOT in your recorded baseline.        [HIGH]
  4. Locally-administered  : a BSSID whose MAC is locally-administered,
     MAC                     common for software/spoofed APs (hostapd,
                             MAC spoofers).                        [MEDIUM]

Usage
-----
  # one-shot scan of the current environment
  sudo ./evil_twin_detector.py -i wlan0

  # record the networks you TRUST as a baseline, once, on a safe network
  sudo ./evil_twin_detector.py -i wlan0 --save-baseline trusted.json

  # later, scan and compare against that baseline (alerts on new BSSIDs)
  sudo ./evil_twin_detector.py -i wlan0 --baseline trusted.json

  # watch continuously, re-scanning every 30s
  sudo ./evil_twin_detector.py -i wlan0 --watch --interval 30

  # parse a previously captured `iw ... scan` dump (no hardware needed)
  ./evil_twin_detector.py --scan-file sample_scan.txt

Educational / authorized-defense use. See repository README and LICENSE.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from collections import defaultdict


# ----------------------------------------------------------------------
#  Scanning
# ----------------------------------------------------------------------
def run_iw_scan(interface):
    """Return raw `iw dev <iface> scan` output, or exit with a clear error."""
    try:
        out = subprocess.run(
            ["iw", "dev", interface, "scan"],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        sys.exit("error: `iw` not found. Install it:  sudo apt install iw")
    except subprocess.TimeoutExpired:
        sys.exit("error: scan timed out (is the interface up?)")

    if out.returncode != 0:
        msg = out.stderr.strip() or "unknown error"
        if "Operation not permitted" in msg or "Permission" in msg:
            sys.exit("error: scanning needs root. Re-run with sudo.")
        sys.exit(f"error: iw scan failed: {msg}")
    return out.stdout


# ----------------------------------------------------------------------
#  Parsing
# ----------------------------------------------------------------------
def parse_scan(text):
    """
    Parse `iw scan` output into a list of AP dicts:
      {bssid, ssid, signal, freq, channel, encryption}
    Pure text parsing — no external dependencies.
    """
    aps = []
    cur = None

    for line in text.splitlines():
        bss = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
        if bss:
            if cur:
                aps.append(cur)
            cur = {
                "bssid": bss.group(1).lower(),
                "ssid": "",
                "signal": None,
                "freq": None,
                "channel": None,
                "has_rsn": False,   # WPA2/3
                "has_wpa": False,   # WPA1
                "privacy": False,   # Privacy capability bit (WEP if no RSN/WPA)
            }
            continue
        if cur is None:
            continue

        s = line.strip()
        if s.startswith("signal:"):
            m = re.search(r"(-?\d+(?:\.\d+)?)", s)
            if m:
                cur["signal"] = float(m.group(1))
        elif s.startswith("freq:"):
            m = re.search(r"(\d+)", s)
            if m:
                cur["freq"] = int(m.group(1))
                cur["channel"] = freq_to_channel(int(m.group(1)))
        elif s.startswith("SSID:"):
            cur["ssid"] = s[len("SSID:"):].strip()
        elif s.startswith("RSN:"):
            cur["has_rsn"] = True
        elif s.startswith("WPA:"):
            cur["has_wpa"] = True
        elif s.startswith("capability:") and "Privacy" in s:
            cur["privacy"] = True

    if cur:
        aps.append(cur)

    for ap in aps:
        ap["encryption"] = classify_encryption(ap)
    return aps


def freq_to_channel(freq):
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if freq == 2484:
        return 14
    if 5180 <= freq <= 5825:
        return (freq - 5000) // 5
    return None


def classify_encryption(ap):
    if ap["has_rsn"]:
        return "WPA2/3"
    if ap["has_wpa"]:
        return "WPA"
    if ap["privacy"]:
        return "WEP"
    return "OPEN"


def is_locally_administered(bssid):
    """
    The 2nd-least-significant bit of the first MAC octet marks a
    locally-administered address. Hardware vendor MACs are globally
    administered (bit clear); software/spoofed APs are often locally
    administered (bit set) — a useful rogue-AP hint, not proof.
    """
    try:
        first_octet = int(bssid.split(":")[0], 16)
    except ValueError:
        return False
    return bool(first_octet & 0b10)


# ----------------------------------------------------------------------
#  Detection
# ----------------------------------------------------------------------
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def detect(aps, baseline=None):
    """Return a list of findings: {severity, title, detail}."""
    findings = []
    by_ssid = defaultdict(list)
    for ap in aps:
        if ap["ssid"]:                       # ignore hidden/blank SSIDs here
            by_ssid[ap["ssid"]].append(ap)

    # --- 1 & 2: per-SSID conflicts -----------------------------------
    for ssid, group in by_ssid.items():
        bssids = {ap["bssid"] for ap in group}
        enc = {ap["encryption"] for ap in group}

        if "OPEN" in enc and len(enc) > 1:
            findings.append({
                "severity": "HIGH",
                "title": f'Encryption downgrade on SSID "{ssid}"',
                "detail": (f"Same SSID advertised with mixed encryption {sorted(enc)} "
                           f"across {len(bssids)} BSSID(s). An open clone of a secured "
                           f"network is the classic evil-twin lure."),
            })

        if len(bssids) > 1:
            sev = "MEDIUM" if baseline is None else "INFO"
            findings.append({
                "severity": sev,
                "title": f'Multiple BSSIDs for SSID "{ssid}"',
                "detail": (f"{len(bssids)} MACs broadcast this SSID: "
                           f"{', '.join(sorted(bssids))}. Normal for enterprise mesh; "
                           f"suspicious for a home/cafe network. Verify against a baseline."),
            })

    # --- 4: locally-administered MACs --------------------------------
    for ap in aps:
        if is_locally_administered(ap["bssid"]):
            findings.append({
                "severity": "MEDIUM",
                "title": f'Locally-administered MAC {ap["bssid"]}',
                "detail": (f'SSID "{ap["ssid"] or "<hidden>"}", {ap["encryption"]}, '
                           f'ch {ap["channel"]}. Software/spoofed APs often use these; '
                           f"real hardware usually does not."),
            })

    # --- 3: baseline deviation ---------------------------------------
    if baseline is not None:
        trusted = {(e["ssid"], e["bssid"].lower()) for e in baseline}
        trusted_ssids = {e["ssid"] for e in baseline}
        for ap in aps:
            if not ap["ssid"]:
                continue
            pair = (ap["ssid"], ap["bssid"])
            if ap["ssid"] in trusted_ssids and pair not in trusted:
                findings.append({
                    "severity": "HIGH",
                    "title": f'Untrusted BSSID for known SSID "{ap["ssid"]}"',
                    "detail": (f'{ap["bssid"]} is broadcasting a trusted SSID but was NOT '
                               f"in your baseline. Possible evil twin impersonating a "
                               f"network you trust."),
                })

    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    return findings


# ----------------------------------------------------------------------
#  Output
# ----------------------------------------------------------------------
COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "INFO": "\033[96m", "_": "\033[0m"}


def supports_color():
    return sys.stdout.isatty()


def tag(sev):
    if supports_color():
        return f"{COLOR[sev]}[{sev}]{COLOR['_']}"
    return f"[{sev}]"


def print_inventory(aps):
    print(f"\nScanned {len(aps)} access point(s):\n")
    print(f"  {'BSSID':<18} {'CH':>3}  {'SIGNAL':>7}  {'ENCRYPT':<8} SSID")
    print(f"  {'-'*17:<18} {'--':>3}  {'------':>7}  {'-------':<8} ----")
    for ap in sorted(aps, key=lambda a: (a["signal"] is None, -(a["signal"] or -999))):
        sig = f'{ap["signal"]:.0f}dBm' if ap["signal"] is not None else "   ?  "
        ch = ap["channel"] if ap["channel"] is not None else "?"
        print(f'  {ap["bssid"]:<18} {str(ch):>3}  {sig:>7}  '
              f'{ap["encryption"]:<8} {ap["ssid"] or "<hidden>"}')


def print_findings(findings):
    print("\n" + "=" * 68)
    if not findings:
        print("  No evil-twin indicators found in this scan.")
        print("=" * 68)
        return
    print(f"  {len(findings)} finding(s):")
    print("=" * 68)
    for f in findings:
        print(f'\n{tag(f["severity"])} {f["title"]}')
        for line in wrap(f["detail"], 64):
            print(f"        {line}")
    print()


def wrap(text, width):
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        out.append(line)
    return out


# ----------------------------------------------------------------------
#  Baseline I/O
# ----------------------------------------------------------------------
def save_baseline(aps, path):
    data = [{"ssid": a["ssid"], "bssid": a["bssid"],
             "encryption": a["encryption"]} for a in aps if a["ssid"]]
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"\nBaseline saved: {len(data)} network(s) -> {path}")


def load_baseline(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        sys.exit(f"error: baseline file not found: {path}")
    except json.JSONDecodeError:
        sys.exit(f"error: baseline file is not valid JSON: {path}")


# ----------------------------------------------------------------------
#  Main
# ----------------------------------------------------------------------
def get_aps(args):
    if args.scan_file:
        try:
            with open(args.scan_file) as fh:
                return parse_scan(fh.read())
        except FileNotFoundError:
            sys.exit(f"error: scan file not found: {args.scan_file}")
    if not args.interface:
        sys.exit("error: provide -i/--interface, or --scan-file for offline parsing.")
    return parse_scan(run_iw_scan(args.interface))


def one_pass(args):
    aps = get_aps(args)
    if args.save_baseline:
        save_baseline(aps, args.save_baseline)
        return
    baseline = load_baseline(args.baseline) if args.baseline else None
    if not args.quiet:
        print_inventory(aps)
    print_findings(detect(aps, baseline))


def main():
    p = argparse.ArgumentParser(
        description="Defensive evil-twin / rogue-AP detector (read-only).")
    p.add_argument("-i", "--interface", help="Wi-Fi interface to scan, e.g. wlan0")
    p.add_argument("--scan-file", help="parse a saved `iw scan` dump instead of scanning")
    p.add_argument("--save-baseline", metavar="FILE",
                   help="record the current networks as a trusted baseline")
    p.add_argument("--baseline", metavar="FILE",
                   help="compare the scan against a saved baseline")
    p.add_argument("--watch", action="store_true", help="scan continuously")
    p.add_argument("--interval", type=int, default=30,
                   help="seconds between scans in --watch mode (default 30)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="hide the AP inventory, show findings only")
    args = p.parse_args()

    if args.watch:
        try:
            while True:
                print(f"\n[{time.strftime('%H:%M:%S')}] scanning...")
                one_pass(args)
                time.sleep(max(5, args.interval))
        except KeyboardInterrupt:
            print("\nstopped.")
    else:
        one_pass(args)


if __name__ == "__main__":
    main()
