# Evil-Twin Detector (defensive tool)

A read-only, blue-team companion to the research in this repository. Where the
rest of the repo *explains* how a rogue-AP captive-portal attack works, this
tool *detects* one. It scans the Wi‑Fi environment and flags access points that
show evil-twin signatures. **It never connects, injects, deauthenticates, or
attacks anything** — it only reads nearby beacon information via `iw`.

## What it detects

| Signal | Severity | Why it matters |
|---|---|---|
| **Encryption downgrade** — one SSID offered both secured *and* open | HIGH | An open clone of a secured network is the classic "free wifi" lure. |
| **Untrusted BSSID for a known SSID** (vs a saved baseline) | HIGH | A new MAC impersonating a network you trust = likely evil twin. |
| **Multiple BSSIDs for one SSID** | MEDIUM / INFO | Normal for enterprise mesh, suspicious for a home/cafe SSID. |
| **Locally-administered MAC** | MEDIUM | Software/spoofed APs (hostapd, MAC spoofers) often use these; real hardware usually doesn't. |

## Requirements

- Linux with `iw` (`sudo apt install iw`)
- Python 3.6+ — **standard library only, no pip installs**
- A Wi‑Fi interface; scanning the air needs root (`sudo`)

## Usage

```bash
# one-shot scan of what's around you
sudo ./evil_twin_detector.py -i wlan0

# record the networks you TRUST, once, while on a known-safe network
sudo ./evil_twin_detector.py -i wlan0 --save-baseline trusted.json

# later: scan and alert on anything that deviates from that baseline
sudo ./evil_twin_detector.py -i wlan0 --baseline trusted.json

# monitor continuously, re-scanning every 30 seconds
sudo ./evil_twin_detector.py -i wlan0 --watch --interval 30

# no hardware? parse a saved `iw scan` dump (also how the demo below runs)
./evil_twin_detector.py --scan-file sample_scan.txt
```

## Try it with no hardware

`sample_scan.txt` is a captured `iw scan` dump containing a planted evil twin:
a legitimate WPA2 `CampusWiFi` mesh plus an **open clone** of it on a
locally-administered MAC. Run:

```bash
./evil_twin_detector.py --scan-file sample_scan.txt
```

and the detector flags the open clone as a HIGH-severity encryption downgrade
while leaving the legitimate mesh and the lone home AP alone. You can produce
your own dump to analyse later with:

```bash
sudo iw dev wlan0 scan > my_scan.txt
```

## How the baseline workflow helps

The single most reliable detection is **baseline deviation**. Record the APs
you trust once (`--save-baseline`), then any future scan that shows a *new* MAC
broadcasting one of those trusted SSIDs is flagged HIGH. That is exactly the
moment an evil twin appears: same name you trust, different radio.

## Limitations (be honest about them)

- A `iw scan` from a managed-mode interface sees beacons the card happens to
  hear; it is not a full monitor-mode capture. For continuous RF monitoring,
  pair this with a WIPS or a monitor-mode sniffer.
- A locally-administered MAC is a *hint*, not proof — some legitimate gear and
  virtualised APs use them too.
- The tool detects; it does not mitigate. Response (PMF/802.11w, 802.1X, user
  warning) is covered in [`../docs/04-defense-and-mitigation.md`](../docs/04-defense-and-mitigation.md).

Educational / authorized-defense use only. See the repository
[`LICENSE`](../LICENSE).
