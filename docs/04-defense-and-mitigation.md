# 04 — Defending Against Evil-Twin & Captive-Portal Attacks

> How to actually stop the attack studied in this repository — organized by who
> owns the control: the network/AP operator, the client/endpoint, and the user.
> This is the part a blue team cares about.

## The core principle

Recall the [attack chain](01-attack-anatomy.md): rogue AP → DHCP → spoofed DNS →
HTTP redirect → fake portal. **Every link is breakable**, and the strongest
defenses cluster at the TLS trust boundary — because, as [doc 02](02-ios-vs-android-detection.md)
showed, everything an evil twin can do with DNS and plain HTTP stops the moment
the client insists on authenticated TLS. Defense-in-depth means putting a
control on as many links as you can.

---

## A. Controls the network / AP operator owns

### A1. 802.11w — Protected Management Frames (PMF)
Many evil-twin attacks begin by **deauthenticating** victims from the real AP to
push them onto the rogue one. PMF (802.11w) cryptographically protects
management frames, defeating the deauth flood that kick-starts the attack.
Enable **WPA3** (PMF mandatory) or **WPA2 with PMF required** fleet-wide.

### A2. Wireless IDS/IPS (WIPS) — rogue-AP detection
A WIPS continuously watches the RF space for an AP broadcasting a **known SSID
with an unexpected BSSID (MAC)**, unexpected channel, or signal characteristics
— the signature of an evil twin. Enterprise controllers (Aruba, Cisco,
Mist/Juniper, Ruckus) do this natively; `Kismet` does it on an open-source
budget. Alert and, where supported, auto-contain.

### A3. 802.1X / WPA-Enterprise instead of a shared PSK
With a shared pre-shared key, anyone who knows the password can stand up a
convincing twin. **WPA2/3-Enterprise (802.1X)** makes the client authenticate
the *network* via a server certificate — a rogue AP can't present the real
RADIUS server's certificate, so a correctly-configured supplicant refuses it.
This is the single strongest AP-side control for managed fleets.

### A4. Legitimate captive portals: do it right
If you *run* a real guest portal, don't train users to accept the exact behavior
an attacker imitates:
- Serve the portal over **HTTPS with a valid, publicly-trusted certificate** on
  a **real domain you own** — never a bare IP, never a self-signed cert.
- Never ask for credentials that matter (email passwords, SSO, "patient ID").
  A guest portal should need an email or a voucher, nothing reusable.

### A5. Client isolation + monitored DHCP/DNS
On the legitimate network, enable **client isolation** (stations can't see each
other) and watch for **rogue DHCP/DNS servers** — a device handing out leases
or answering DNS that isn't your infrastructure is a red flag.

---

## B. Controls the client / endpoint owns (the strongest layer)

[Doc 02](02-ios-vs-android-detection.md) demonstrated that **client design
alone can defeat this attack**. Harden endpoints toward that behavior:

### B1. HSTS — and HSTS preloading
HTTP Strict Transport Security tells a browser "only ever reach this site over
HTTPS." A **preloaded** HSTS domain can't be downgraded to HTTP even on first
visit — so the attacker's plain-HTTP redirect to a cloned login page simply
won't load for any serious site. This is why the evil twin can only ever catch
HTTP or never-visited sites; every HSTS-preloaded domain is immune to the
redirect.

### B2. Certificate pinning (apps)
Mobile apps that **pin** their server's certificate reject any TLS session that
doesn't present the expected cert — so even a forged-CA attacker (far beyond a
basic evil twin) can't MITM them. Banking and messaging apps should pin; it's a
developer control worth asking vendors about.

### B3. Encrypted DNS (DoH / DoT)
The entire attack depends on controlling DNS. **DNS-over-HTTPS** or
**DNS-over-TLS** sends the client's lookups to a trusted resolver inside an
encrypted channel the rogue AP can't read or spoof. When the client's DNS can't
be hijacked, the "every domain resolves to the attacker" step collapses. Enable
DoH/DoT in the browser and OS, and push it via MDM on managed devices.

> Caveat: encrypted DNS can interfere with *legitimate* captive portals. Mature
> OSes special-case the captive-detection domains in the clear and switch to
> encrypted DNS once past the portal. This is a feature, not a reason to disable
> DoH.

### B4. OS captive-detection behavior
Prefer and keep updated the OS behavior shown to resist the attack in
[doc 02](02-ios-vs-android-detection.md): **HTTPS-first captive checks that do
not silently downgrade to HTTP**, plus **DNS anti-spoof probes** (random-domain
`NXDOMAIN` checks). On managed fleets, keep clients patched — detection logic
hardens over OS versions.

### B5. Always-on VPN
A client VPN that comes up **before** general traffic turns the hostile Wi‑Fi
into a dumb transport: DNS, HTTP, everything rides an encrypted tunnel the rogue
AP can't inspect or redirect. For a travelling workforce this is the pragmatic
blanket control. (It still needs the initial captive portal to be passed, so
pair it with user awareness.)

---

## C. Controls the user owns (awareness)

Technical controls fail against a user who types their password into anything.
Train for these habits:

1. **Treat any "login" captive portal with suspicion.** A real guest network
   almost never needs your email/SSO password. If a coffee-shop Wi‑Fi asks for
   your Google or banking password, it's an attack.
2. **Check the address bar.** A portal on a **bare IP** (`10.0.0.1`) or a
   look‑alike domain **without a valid padlock** is a red flag. (Attackers work
   hard to fake a plausible domain in the bar precisely because users are taught
   to check it — so "domain looks fine" is necessary, not sufficient.)
3. **Don't auto-join open networks.** Turn off "auto-join" for open/unknown
   SSIDs so your device doesn't silently attach to a twin. **"Forget" networks**
   you won't reuse — devices re-advertising known SSIDs are what twins exploit.
4. **Use mobile data for anything sensitive on untrusted Wi‑Fi**, or an
   always-on VPN (B5).
5. **Report** a Wi‑Fi network that asks for credentials it shouldn't — to venue
   staff and, in an org, to security.

---

## Quick reference: control vs. attack step

| Attack step | Primary control(s) |
|---|---|
| Deauth to force victim onto twin | **802.11w / PMF** (A1) |
| Rogue AP broadcasting your SSID | **WIPS** (A2), **802.1X** (A3) |
| Victim's device trusts the rogue network | **802.1X server-cert auth** (A3) |
| Spoofed DNS points everything at attacker | **DoH/DoT** (B3) |
| HTTP redirect to fake portal | **HSTS (preload)** (B1), **OS no-downgrade** (B4) |
| Fake page harvests credentials | **cert pinning** (B2), **user awareness** (C1–C2) |
| Everything, as a blanket | **Always-on VPN** (B5) |

---

## The one-line summary

> An evil-twin captive portal is a chain of legitimate features abused in
> sequence. You don't need to beat all of it — **break any link**. The cheapest
> high-impact links are **encrypted DNS** and **HSTS** on the client (they gut
> the DNS-spoof and HTTP-redirect steps) and **802.11w + WIPS** on the network
> (they stop the victim being pushed onto the twin in the first place). The
> ceiling of the whole attack class is **TLS trust** — which is exactly why a
> well-configured modern client, as the iOS capture showed, can refuse the
> attack outright.
