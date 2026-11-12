# 01 — Anatomy of a Captive-Portal Evil Twin

> Conceptual walkthrough of how a rogue-AP captive-portal attack works, layer
> by layer. No tooling or payloads — this is the mental model a defender needs
> in order to recognize and break the attack.

## What the attack is

An **evil twin** is a rogue Wi‑Fi access point that impersonates a legitimate
or plausible network ("Guest WiFi", "Free Public WiFi", or a clone of a real
SSID). A **captive portal** layered on top of it is a web page the victim is
forced to see before getting internet — the same mechanism hotels and airports
use legitimately. Combined, the attacker gets a victim to connect, intercepts
their first web request, and presents a fake login page to harvest whatever the
page asks for.

The attack is interesting precisely because **every individual piece is a
normal, legitimate networking feature** — running an AP, handing out DHCP
leases, answering DNS, redirecting HTTP. The maliciousness is only in the
combination and intent. That is also why defending against it is subtle.

## The 7-layer dependency model

During the lab I found it essential to reason about the system as a stack where
**each layer depends on the one below it**. If a lower layer silently breaks,
every layer above it fails in confusing ways — which is exactly what makes this
hard to debug (see [doc 03](03-debugging-noprefixroute.md)).

```
Layer 7  Data store        — where harvested input would land
Layer 6  Web server        — serves the portal page, handles the POST
Layer 5  DNS spoofing      — every domain resolves to the attacker
Layer 4  Firewall / NAT    — redirect victim HTTP to the local portal
Layer 3  Routing           — kernel must know how to reach the victim  ← fragile
Layer 2  Rogue AP          — hostapd turns the card into an access point
Layer 1  Radio interface   — the Wi-Fi adapter, in AP ("Master") mode  ← foundation
```

### Layer 1 — Radio interface
A Wi‑Fi adapter that supports **AP mode** (not all do — this is a hardware
capability you must verify). In the lab, one adapter was put into AP/"Master"
mode for the rogue network while a second adapter kept the attacker online.
Using a single adapter for both roles is impossible: a radio is either a client
*or* an access point on a given channel, not both.

### Layer 2 — Rogue access point
Software (`hostapd`) drives the adapter as an access point, broadcasting a
chosen SSID. The victim sees a normal Wi‑Fi network. Nothing here is
technically different from a real home router's AP function.

### Layer 3 — Routing (the fragile layer)
The attacker's host must have a kernel route telling it that the victim's
subnet lives on the AP interface. This sounds trivial and is usually automatic
— but it is the single most fragile link in the chain, because the *way* you
assign the interface IP determines whether that route is created at all. This
is the subject of the entire [doc 03](03-debugging-noprefixroute.md) case
study.

### Layer 4 — Firewall / NAT redirect
Packet-filter rules do two jobs: **forward** the victim's traffic toward the
real internet (so the connection feels real), and **redirect** the victim's
plain-HTTP requests to the local portal instead of their intended destination.
This "transparent redirect" is the mechanism that puts the fake page in front
of the victim without them typing anything.

### Layer 5 — DNS spoofing
A local DNS responder answers **every** lookup with the attacker's own IP. So
when the victim's device checks `connectivitycheck.gstatic.com` or
`captive.apple.com`, it is pointed at the attacker. This is the trigger for the
OS "Sign in to network" popup — and, crucially, the behavior here is where iOS
and Android diverge sharply (see [doc 02](02-ios-vs-android-detection.md)).

### Layer 6 — Web server
A plain web server hosts the portal page and receives whatever the victim
submits. The rewrite logic sends essentially any requested URL to the portal.

### Layer 7 — Data store
Where submitted input would be recorded. In a real attack this is the whole
point; in defensive study it is the least interesting layer and the one this
repository deliberately does not implement.

## How the layers chain at runtime

```
victim joins SSID
   └─► DHCP lease from attacker (IP, gateway, DNS = attacker)
         └─► OS "connectivity check" fires automatically
               └─► DNS spoof → check resolves to attacker
                     └─► OS opens a browser to the check URL over HTTP
                           └─► firewall redirect → attacker's web server
                                 └─► portal page shown (OS shows "Sign in")
                                       └─► victim submits → stored → redirected on
```

The elegant, and alarming, part is that steps 2–5 happen **automatically**, with
no victim action, because captive-portal detection is a built-in OS feature.
The attacker is hijacking a convenience mechanism.

## Why understanding this matters for defense

Every arrow above is a place a defender can break the chain:

- **Layer 1–2:** rogue-AP detection (WIPS) spots a second AP broadcasting a
  known SSID with the wrong BSSID.
- **Layer 5:** DNS-over-HTTPS on the client bypasses the spoofer entirely.
- **Layer 4/6:** HSTS and certificate pinning make the HTTPS downgrade fail, so
  the transparent redirect never reaches a page the victim trusts.
- **Client behavior:** the OS captive-detection logic itself is a defense — and
  [doc 02](02-ios-vs-android-detection.md) shows one major OS resisting the
  attack outright because of it.

The defenses are developed fully in
[doc 04](04-defense-and-mitigation.md).
