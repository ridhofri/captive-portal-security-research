# 02 — Captive-Portal Detection: iOS vs Android

> A first-hand comparison of how two mobile operating systems decide "is there
> internet here, or a captive portal?" — and why that single design choice
> determined whether a transparent-redirect attack worked. Backed by packet
> captures taken in the lab.

## Why this matters

Captive-portal **detection** is a client-side convenience feature: when you join
a Wi‑Fi network, your phone quietly checks whether it really has internet, and
if not, pops up a "Sign in to network" sheet. That same feature is what a
rogue-AP attacker relies on to auto-present a fake portal.

So the client's detection logic is simultaneously the attacker's **trigger** and
the defender's **control point**. The lab compared an iPhone (iOS 15) and an
Android 8.1 device (Samsung) against the identical rogue AP. They behaved very
differently.

## How each OS probes

| | iOS (observed) | Android (observed) |
|---|---|---|
| Probe host | `captive.apple.com` | `connectivitycheck.gstatic.com`, `www.google.com/generate_204` |
| Preferred transport | **HTTPS first** | HTTP `generate_204` |
| Expected "has internet" answer | signed/expected HTTPS response | `HTTP 204 No Content` |
| On mismatch | tends to **refuse** rather than downgrade | shows "Sign in", follows HTTP redirect |
| DNS anti-spoof check | queries random nonexistent `*.icu`-style names, expects `NXDOMAIN` | less aggressive |

The decisive difference: **iOS attempts its captive check over HTTPS and does
not readily fall back to plain HTTP.** Android's primary check is a plain-HTTP
`generate_204`, which *can* be transparently redirected.

## The iOS result: the attack's redirect did not fire

With DNS spoofed so that every name resolved to the attacker, the iPhone issued
a storm of lookups for Apple services and then, repeatedly, **random
non-existent domains** — an anti-spoofing probe. Because the spoofer answered
*everything* with one IP, those random names did **not** come back as the
expected `NXDOMAIN`, which is a strong "this DNS is lying" signal.

Observed DNS pattern (abridged, from the lab capture):

```
query[A]   captive.apple.com            → (spoofed to attacker IP)
query[A]   <random>.icu                 → should be NXDOMAIN on honest DNS
query[HTTPS] captive.apple.com          → REFUSED by the spoofer (no HTTPS record)
```

And at the TCP layer, when the attacker tried to *force* the issue by blocking
HTTPS (so the device might fall back to HTTP), the iPhone's connection attempts
were captured going **only to port 443**, retrying, and **never downgrading to
port 80** — the port the transparent redirect controlled:

```
10.0.0.x.xxxxx > 17.57.145.x.443: Flags [S]      ← HTTPS attempt
10.0.0.x.xxxxx > 17.57.145.x.443: Flags [S]      ← retry
10.0.0.x.xxxxx > 17.57.145.x.443: Flags [S]      ← retry
(no SYN to :80 — iOS does not fall back to HTTP)
```

**Interpretation:** iOS's "HTTPS-first, no silent HTTP-downgrade" captive check
is itself an anti-hijack control. When HTTPS can't be satisfied legitimately
(the attacker has no valid certificate for `captive.apple.com`), iOS prefers to
report "no internet" rather than trust a plain-HTTP page. The transparent-HTTP
redirect — the core of the attack — never gets a client that will use it.

This is a genuinely interesting defensive finding: **Apple's captive-detection
design defeats the naive transparent-redirect evil twin by refusing to
downgrade.** Beating it would require defeating TLS itself (a trusted forged
certificate, which requires installing a rogue CA on the victim device — an out-
of-scope, far more invasive attack).

## The Android result: it followed the HTTP redirect

Android 8.1 behaved as its design predicts. Its connectivity check uses
plain-HTTP `generate_204`, expecting an empty `204 No Content`. When the lab
served a normal page instead of a 204, Android concluded "captive portal
present" — exactly the legitimate behavior — and was willing to proceed over
HTTP, which the attacker controlled.

Captured, the Android device **did** complete a TCP three-way handshake to the
attacker's port 80 and issued its `generate_204` / `GET /` over HTTP:

```
10.0.0.87 > 10.0.0.1.80: [S]      ← SYN
10.0.0.1  > 10.0.0.87.80: [S.]    ← SYN-ACK  (handshake completes)
10.0.0.87 > 10.0.0.1.80: [.]      ← ACK
10.0.0.87 > 10.0.0.1.80: GET / HTTP/1.1  (User-Agent: Dalvik ... Android 8.1.0)
```

The difference between a bare `[S]` storm (iOS) and a completed
`[S] / [S.] / [.] / GET` (Android) is the entire story in two captures.

> **Note:** getting even Android to complete that handshake required fixing a
> routing bug on the attacker host first — the SYN-ACK was being dropped for an
> unrelated reason. That debugging story is
> [doc 03](03-debugging-noprefixroute.md), and it's a reminder that "the client
> is secure" and "my tooling is broken" can look identical from the outside.

## The takeaway for defenders

1. **Client OS design is a real defense layer.** HTTPS-first captive detection
   with no HTTP downgrade (iOS's model) materially resists transparent-redirect
   evil twins. Pushing an organization's fleet toward clients and settings that
   behave this way is a legitimate hardening step.
2. **Plain-HTTP connectivity checks are the weak link.** Any device that trusts
   an unauthenticated HTTP `204`/redirect can be funneled into a fake portal.
3. **DNS anti-spoofing probes work.** The random-domain `NXDOMAIN` check is a
   cheap, effective "is this resolver honest?" test. DNS-over-HTTPS on the
   client removes the attacker's DNS control entirely.
4. **The ceiling of this attack class is TLS.** Everything the attacker can do
   with DNS + HTTP redirect stops at the TLS trust boundary. That is why the
   defenses in [doc 04](04-defense-and-mitigation.md) lean so heavily on HSTS,
   certificate pinning, and encrypted DNS.
