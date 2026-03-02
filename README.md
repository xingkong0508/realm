# 🌌 Realm: The Entropy Law Engine

> "We observe the physics of the network, not just the signatures. Your server, your sovereignty."

Realm is a next-generation, ultra-lightweight network defense engine built on eBPF (XDP) and Shannon Entropy. Deployed at the deepest layer of the Linux kernel (Ring 0), it calculates the microscopic thermodynamic properties of network packets in real-time. Instead of relying on bloated virus databases, Realm physically severs unknown threats, 0-day exploits, and volumetric scanners in nanoseconds based on the laws of physics and mathematics.

## ⚠️ WARNING: Highly Aggressive Defense (Read Before Running)

Realm V6.7+ is a weapon of absolute perimeter defense. The entropy-based physical severing is extremely aggressive.

**While Realm now includes Core Protocol Whitelisting (TCP/UDP 22, 443, 53) and Dynamic Admin IP Exemption**, misconfigurations can still lock you out of your own server.

* Always use the provided `update_admin.sh` to exempt your current SSH IP before unleashing the engine.
* Please test it thoroughly in a VM or a staging environment first. You have been warned.

## ⚔️ Architectural Rigor: How Realm Annihilates Malicious Traffic

Traditional WAFs rely on lagging signature matching. Realm embraces a **Local-First Dimensional Strike**, utilizing the following rigorous mechanisms:

1. **Shannon Entropy as a Metric:** Malicious payloads—such as packed malware, encrypted reverse shells, or overflow probing—inevitably cause violent fluctuations in the "Information Entropy" (byte distribution) of network packets. Realm calculates the Shannon entropy of the first 64 bytes of incoming payloads. Traffic deviating from your server's dynamically established thermodynamic baseline (EWMA) is classified as an anomaly and severed.
2. **Nanosecond XDP Dropping:** Upon identifying a threat, Realm executes an `XDP_DROP` action directly at the Network Interface Controller (NIC) driver layer. The malicious packet is physically destroyed before it can allocate socket buffers (SKBs) or reach the Linux network stack (`iptables`/`netfilter`), making Realm immune to high-frequency DDoS and scanning exhaustion.
3. **Anti-Exhaustion Memory Architecture:** Banned IPs are stored in a kernel-space eBPF `LRU_HASH` (Least Recently Used) map. Unlike standard hash maps that cause memory exhaustion (OOM) under heavy botnet scanning, Realm's `LRU_HASH` automatically evicts the oldest records when the 10,240-entry capacity is reached, guaranteeing eternal system stability.
4. **HoneyTokens & Dynamic Punishment:** Realm silently inspects payloads for sensitive plaintext tokens (e.g., `admin`, `passwd`). A match indicates a deterministic attack, triggering an immediate IP ban and forcing the Law Engine into a "High-Tension Punishment" state (escalating the K-value sensitivity) for a 5-minute cooldown period.
5. **Forensic Telemetry:** While defending, Realm translates binary payloads into readable ASCII and cross-references IPs with the GeoLite2 database, logging all thermodynamic judgments into a structured `realm_forensics.csv` for post-mortem analysis.

## 🚀 Quick Start & Deployment Guide

**Prerequisites:** Linux Kernel 5.8+ (with eBPF/XDP enabled), `clang`, and Go 1.25+.

```bash
# 1. Clone the repository
git clone https://github.com/xingkong0508/realm.git
cd realm

# 2. Compile eBPF bytecode (Requires clang)
go generate ./...

# 3. Build the Sovereign Engine
go build -o realm_engine .

# 4. Secure your access (CRITICAL!)
# This script automatically updates your current SSH IP as the absolute whitelist
chmod +x update_admin.sh
./update_admin.sh

# 5. Unleash Sovereign Mode
# Inject your private Law parameters, specify your public NIC (e.g., ens4), and your admin IP
sudo REALM_DIVIDER=0.95 REALM_MULTIPLIER=1.50 ./realm_engine -iface ens4 -admin YOUR_IP_HERE

```

## 🛠️ Troubleshooting & Operational Manual

**Error 1: `Can't replace active BPF XDP link` or `Device or resource busy**`

* **The Cause:** A previous instance of Realm crashed or was killed (`kill -9`) without properly detaching its hooks from the NIC.
* **The Fix:** Forcefully sever the dangling XDP program using `bpftool` and clear the BPF filesystem.
```bash
sudo bpftool net detach xdp dev <your_interface>
sudo bpftool net detach xdpgeneric dev <your_interface>
sudo rm -rf /sys/fs/bpf/*

```



**Error 2: Administrator SSH Connection Dropped/Locked Out**

* **The Cause:** You did not provide the `-admin <IP>` flag, or your dynamic IP changed, causing Realm to classify your encrypted SSH stream as an entropy anomaly.
* **The Fix:** Log in via your cloud provider's out-of-band Serial Console (VNC/Web Console), stop the `realm_engine` process, and re-run `./update_admin.sh`.

**Error 3: Compilation Failure (`use of undeclared identifier 'IPPROTO_TCP'`)**

* **The Cause:** The C compiler cannot find the Linux networking dictionary.
* **The Fix:** Ensure `#include <linux/in.h>` and `#include <linux/tcp.h>` are declared at the very top of `bpf/probe.c`.
