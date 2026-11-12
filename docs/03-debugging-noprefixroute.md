# 03 — Debugging Case Study: The Silently-Dropped SYN-ACK

> A multi-hour network fault where **every client silently failed to load the
> portal**, root-caused to a single kernel routing flag. This document is about
> **methodology** — how to isolate a fault that produces no error message — not
> about the attack. The techniques transfer directly to NOC / network-ops work.

## The symptom

- The rogue AP was up. Clients associated and got DHCP leases.
- From the attacker host itself, `curl http://10.0.0.1/` returned the page fine.
- From **every actual client**, the portal never loaded. No error. Just a
  hang, then the device giving up and showing "no internet".

A fault that works locally but fails for every remote client, **with no log
line anywhere**, is the hardest class to debug. There is nothing to grep for.

## The methodology: isolate the layer, don't guess

The discipline that eventually cracked it: **follow the packet, one layer at a
time, and demand evidence at each hop** rather than theorizing about causes.
The [7-layer model](01-attack-anatomy.md) gave the order to check things in.

### Step 1 — Prove the request leaves the client and arrives
`tcpdump` on the AP interface showed the client's SYN **arriving**:

```
10.0.0.87 > 10.0.0.1.80: Flags [S]   ← client SYN, repeated
10.0.0.87 > 10.0.0.1.80: Flags [S]   ← retransmit
10.0.0.87 > 10.0.0.1.80: Flags [S]   ← retransmit
```

So: the request reaches the host. But there is **no `[S.]` (SYN-ACK) going
back**. The server never answers. That rules out everything on the client side
and points at the host.

### Step 2 — Prove the server itself is healthy
`curl` to `10.0.0.1` locally returned `200 OK`. The web server works. So the
server is fine *and* the SYN arrives, yet no SYN-ACK goes out. The gap is
between "kernel received SYN" and "kernel sent the reply". That is a
**kernel/network-stack** problem, not an application one.

### Step 3 — Check the firewall (and clear it as a suspect)
Firewall INPUT policy was `ACCEPT`; no rule was dropping port 80. A LOG rule
confirmed the SYN **did reach the INPUT chain**. So the packet gets all the way
to the kernel's socket layer. Still no reply. The firewall is not the culprit.

### Step 4 — Ask the kernel what it's dropping
This is the pivotal step. Instead of guessing, ask the kernel directly for its
own drop counters:

```
netstat -s | grep -iE 'drop|route'
   ...
   13 dropped because of missing route
   TCPSynRetrans: 258
```

**"dropped because of missing route."** The kernel *received* the SYN, *wanted*
to send a SYN-ACK back to `10.0.0.87`, and then **had no route to get there**,
so it silently discarded its own reply. That is why there was no error on any
device and no firewall hit — the drop happened inside the host's routing
decision for the outbound reply.

This single counter is the whole case. `netstat -s` (and `nstat`) is the most
underused tool in this class of problem: the kernel is keeping score of exactly
why it drops packets, and almost nobody looks.

### Step 5 — Confirm the missing route
```
ip route show | grep 10.0.0     → (nothing)
ip addr show wlan0 | grep inet  → inet 10.0.0.1/24 ... noprefixroute wlan0
ip route get 10.0.0.87          → 10.0.0.87 via <uplink> dev wlan1   ← WRONG
```

The interface **had** its IP (`10.0.0.1/24`) but there was **no connected route
for `10.0.0.0/24`**. So the kernel, asked "how do I reach `10.0.0.87`?",
fell through to the default route and tried to send the SYN-ACK out the
*uplink* interface — where it was, correctly, dropped. The reply was being
routed out the wrong door.

## The root cause: `ifconfig` vs `ip addr`

The telltale was the `noprefixroute` flag on the address. The interface IP had
been assigned with legacy `ifconfig`:

```
ifconfig wlan0 10.0.0.1 netmask 255.255.255.0
```

On a modern Linux stack, this assigns the address but, in the observed
behavior, left the connected subnet route uninstalled (`noprefixroute`) — the
address existed with no matching `10.0.0.0/24 dev wlan0` route. The kernel knew
its own IP but not that the subnet lived on that interface.

### The fix
Assign addresses with `iproute2`, which installs the prefix route atomically:

```
ip addr flush dev wlan0
ip addr add 10.0.0.1/24 dev wlan0
```

After which:

```
ip route show | grep 10.0.0   → 10.0.0.0/24 dev wlan0 proto kernel scope link src 10.0.0.1
ip route get 10.0.0.87        → 10.0.0.87 dev wlan0 src 10.0.0.1    ← correct now
```

And the capture immediately changed from a one-way SYN storm to a complete
handshake:

```
10.0.0.87 > 10.0.0.1.80: [S]
10.0.0.1  > 10.0.0.87.80: [S.]   ← SYN-ACK now returns
10.0.0.87 > 10.0.0.1.80: [.]
10.0.0.87 > 10.0.0.1.80: GET / HTTP/1.1
```

## Why `curl` lied (the trap that cost hours)

Local `curl` to `10.0.0.1` always worked **because loopback traffic never needs
the subnet route** — the kernel short-circuits `10.0.0.1 → 10.0.0.1` through
`lo` and never consults the broken `10.0.0.0/24` path. So the one test that was
easiest to run (`curl` on the host) was the one test that could *never* reveal
the bug. Every remote client, whose reply genuinely had to be routed out
`wlan0`, hit the missing route and failed.

**Lesson:** a local self-test can pass while every real client fails, if the
self-test takes a different path through the stack than real traffic does.
Always reproduce with traffic that exercises the same path as production.

## Transferable lessons (the portfolio point)

1. **Follow the packet, demand evidence per hop.** SYN arrives? SYN-ACK leaves?
   Each `tcpdump`/counter answer eliminates whole categories of cause.
2. **`netstat -s` / `nstat` are first-class tools.** The kernel already knows
   why it dropped your packet. "dropped because of missing route" ended a
   multi-hour hunt in one line.
3. **`ip` over `ifconfig`.** `ifconfig` is deprecated and its address-assignment
   behavior around connected routes is a genuine foot-gun. Use `iproute2`.
4. **Distinguish "secure" from "broken".** For a while this looked like the
   clients were defending themselves; it was actually a host misconfiguration.
   Knowing the difference is the core NOC skill.
5. **Beware self-tests that bypass the fault.** Loopback `curl` success masked a
   total remote failure.

These are exactly the habits a NOC / network-engineering role is hiring for —
which is why this bug, not the attack, is the most valuable thing in this
repository.
