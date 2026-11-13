# Captive Portal Security Research — Evil Twin Attack & Defense Analysis

> **Educational / authorized security research.** This repository documents a
> controlled lab study of rogue access point ("evil twin") captive portal
> attacks, the operating-system defenses that resist them, and the
> network-troubleshooting methodology used along the way. It contains
> **analysis, packet-capture evidence, and defensive guidance only** — no
> ready-to-run attack tooling, no harvesting scripts, and no captured data.

**Author:** Ridhofir Fikri Shodiq (Arceryx) · Telecommunications Engineering, Politeknik Negeri Malang
**Domain:** Network Security · NOC · Wireless

---

## Why this repository exists

Anyone can download an evil-twin script. What a rogue-AP study is actually
*worth* — to a defender or an employer — is the understanding it produces:

1. **How the attack really works**, layer by layer, end to end.
2. **Why modern clients resist it**, proven with first-hand packet captures
   (iOS vs Android captive-portal detection behaved very differently).
3. **How to troubleshoot a deep network fault methodically** — a multi-hour
   bug where every client silently failed was root-caused to a single
   kernel routing flag (`noprefixroute`), using `netstat -s`, kernel logs,
   and TCP three-way-handshake analysis in `tcpdump`.
4. **How defenders stop it** — the concrete controls, at the AP, the network,
   and the client.

This repo is deliberately framed around **detection and defense**. The attack
was performed in a self-contained lab to understand it; the deliverable is the
knowledge and a defensive detector, not a weapon. The one piece of runnable
code here — [`tools/evil_twin_detector.py`](tools/evil_twin_detector.py) —
*detects* evil twins; it does not create them.

---

## Contents

| Document | What it covers |
|---|---|
| [`docs/01-attack-anatomy.md`](docs/01-attack-anatomy.md) | How a captive-portal evil twin works, layer by layer (AP → DHCP → DNS → redirect → portal). Conceptual, with the 7-layer dependency model used to reason about it. |
| [`docs/02-ios-vs-android-detection.md`](docs/02-ios-vs-android-detection.md) | Captive-portal detection on iOS vs Android, with annotated packet captures. Why one resisted a transparent redirect and the other didn't. |
| [`docs/03-debugging-noprefixroute.md`](docs/03-debugging-noprefixroute.md) | A network-troubleshooting case study: diagnosing silently-dropped SYN-ACKs down to `ifconfig`'s `noprefixroute` behavior. Methodology over tools. |
| [`docs/04-defense-and-mitigation.md`](docs/04-defense-and-mitigation.md) | How to actually defend against evil-twin / captive-portal attacks — at the AP, the network, and the client. The part that matters for a blue team. |
| [`tools/evil_twin_detector.py`](tools/evil_twin_detector.py) | **Defensive tool.** A read-only Python scanner (stdlib only) that detects rogue-AP / evil-twin signatures — encryption downgrades, untrusted BSSIDs vs a baseline, spoofed MACs. See [`tools/README.md`](tools/README.md). |

---

## What is deliberately NOT here

To keep this responsible and portfolio-appropriate:

- No fake-portal HTML, no credential-harvesting script, no DB schema.
- No one-command launcher for `hostapd` / `dnsmasq` / `iptables`.
- No captured credentials or any personal data.

If you are studying this to *defend* a network, the four documents give you
the full mental model without a deployable attack. That is the point.

---

## Lab environment (for reproducibility of the *analysis*)

- **OS:** Kali Linux (rolling)
- **Hardware:** two 802.11 adapters — one Atheros `ath9k` (AP-capable), one
  used as the uplink client
- **Topology:** `wlan0` = rogue AP interface · `wlan1` = internet uplink ·
  isolated `10.0.0.0/24` client subnet
- **Scope:** author's own devices on an isolated lab segment

---

## Ethics & legal

Rogue access point and captive-portal credential capture are **illegal**
against people or networks you do not own or have **written** authorization to
test. In Indonesia this engages **UU ITE** and **UU PDP** (personal-data
protection); equivalents exist worldwide (CFAA in the US, the Computer Misuse
Act in the UK, etc.).

This research was conducted in a self-contained lab. Use the knowledge here to
**build defenses**, run **authorized** assessments with a signed scope, or
teach — never to attack others.

See [`LICENSE`](LICENSE) and [`docs/04-defense-and-mitigation.md`](docs/04-defense-and-mitigation.md).
