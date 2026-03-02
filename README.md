# 🌌 Realm: The Entropy Law Engine

> "We observe the physics of the network, not just the signatures. Your server, your sovereignty."

Realm is a next-generation, ultra-lightweight network defense engine built on eBPF (XDP) and Shannon Entropy. Deployed at the deepest layer of the Linux kernel (Ring 0), it calculates the microscopic thermodynamic properties of network packets in real-time. Instead of relying on bloated virus databases, Realm physically severs unknown threats, 0-day exploits, and volumetric scanners in nanoseconds based on the strict laws of physics and mathematics.

## ⚠️ WARNING: Highly Aggressive Defense (Read Before Running)

Realm V6.7+ is a weapon of absolute perimeter defense. The entropy-based physical severing is extremely aggressive.

**While Realm now includes Core Protocol Whitelisting (TCP/UDP 22, 443, 53) and Dynamic Admin IP Exemption**, misconfigurations can still lock you out of your own server.

* Always use the provided `update_admin.sh` to exempt your current SSH IP before unleashing the engine.
* Please test it thoroughly in a VM or a staging environment first. You have been warned.

## 👁️ Why Realm? (A Reflection on the Industry)

The cybersecurity landscape has long been trapped in the quagmire of traditional, bloated security software.

1. **Lagging Signature Matching:** Traditional WAFs and Antivirus software are perpetually one step behind attackers. They rely on bloated "virus databases" or rigid Regular Expressions. Faced with mutated payloads, polymorphic malware, or novel 0-day exploits, they are virtually blind.
2. **Suffocating Operational Bloat:** To artificially stack commercial features, security agents often consume excessive CPU and memory resources, ironically dragging down the business operations they are deployed to protect.
3. **Loss of Sovereignty and Privacy:** Many commercial security tools, under the guise of "Cloud Threat Intelligence," recklessly upload your server's raw traffic, logs, and even full PCAPs to centralized corporate servers. **You are paying for a black box that constantly surveils you.**

## 🏰 Core Philosophy: Local-First

In this cloud-native era where data is arbitrarily harvested by third parties, Realm firmly embraces the **Local-First** philosophy.

* **Absolute Data Privacy:** Realm operates exclusively at the NIC driver layer (XDP). All traffic observation, baseline calculation, and interception judgments are completed in a closed loop within your local machine's memory. **Not a single byte of user data leaves your NIC. Your data belongs only to you.**
* **Kernel-Level Transparency & Stability:** As a privileged program running at Ring 0, trust is paramount. Realm's core logic is 100% open-source. It incorporates an internal memory fuse (auto-terminating if memory exceeds 100MB) to guarantee it will never exhaust server resources.

## ⚔️ Architecture & Defense Mechanics

Traditional WAFs rely on lagging signature matching. Realm embraces a **Local-First Dimensional Strike**, utilizing the following rigorous engineering mechanisms:

1. **The Genesis Period (Baseline Calibration):** Upon deployment, Realm does not blindly block traffic. The first 5,000 packets are strictly observed to calculate a localized thermodynamic baseline using an Exponentially Weighted Moving Average (EWMA).
2. **Shannon Entropy as a Metric:** Malicious payloads—such as packed malware, encrypted reverse shells, or overflow probing—inevitably cause violent fluctuations in the byte distribution of network packets. Realm utilizes the Shannon Entropy formula ($H(X) = -\sum P(x_i) \log_2 P(x_i)$) on the first 64 bytes of payloads. Traffic deviating from the local EWMA baseline is classified as an anomaly and severed.
3. **Nanosecond XDP Dropping:** Upon identifying a threat, Realm executes an `XDP_DROP` action directly at the Network Interface Controller (NIC) driver layer. Malicious packets are physically destroyed before allocating socket buffers (SKBs), making Realm immune to high-frequency DDoS and scanning exhaustion.
4. **Anti-Exhaustion Memory Architecture:** Banned IPs are stored in a kernel-space eBPF `LRU_HASH` (Least Recently Used) map. Unlike standard hash maps that cause memory exhaustion (OOM) under heavy botnet scanning, Realm's `LRU_HASH` automatically evicts the oldest records when the 10,240-entry capacity is reached, ensuring continuous stability.
5. **HoneyTokens & Dynamic Punishment:** Realm silently monitors for deterministic probing strings (e.g., `admin`, `passwd`). Triggering a HoneyToken results in an immediate IP ban and forces the Law Engine into a "High-Tension Punishment State," escalating the K-value sensitivity to rigorously filter subsequent traffic for a 5-minute cooldown.
6. **Adversarial Noise Poisoning:** To counter automated AI vulnerability scanners, Realm introduces a 1% probability of intentionally flipping the judgment result, poisoning the attacker's machine-learning training models.
7. **Forensic Telemetry:** While defending, Realm translates binary payloads into readable ASCII and cross-references IPs with the GeoLite2 database, logging all thermodynamic judgments into a structured `realm_forensics.csv` for local post-mortem analysis.
8. **Sovereign Control:** While the code is open-source, the Threshold Laws are controlled by the deployer via environment variables (`REALM_DIVIDER` & `REALM_MULTIPLIER`). **The ultimate interpretation of the Law always remains in the hands of the deployer.**

## 🚀 Quick Start & Deployment Guide

**Prerequisites:** Linux Kernel 5.8+ (with eBPF/XDP enabled), `clang`, Go 1.25+, and `GeoLite2-Country.mmdb` placed in the project root.

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

* **Error 1: `Can't replace active BPF XDP link` or `Device or resource busy**`
* **The Cause:** A previous instance of Realm crashed or was killed (`kill -9`) without properly detaching its hooks from the NIC.
* **The Fix:** Forcefully sever the dangling XDP program using `bpftool` and clear the BPF filesystem.
```bash
sudo bpftool net detach xdp dev <your_interface>
sudo bpftool net detach xdpgeneric dev <your_interface>
sudo rm -rf /sys/fs/bpf/*

```

* **Error 2: Administrator SSH Connection Dropped/Locked Out**
* **The Cause:** You did not provide the `-admin <IP>` flag, or your dynamic IP changed, causing Realm to classify your encrypted SSH stream as an entropy anomaly.
* **The Fix:** Log in via your cloud provider's out-of-band Serial Console (VNC/Web Console), stop the `realm_engine` process, and re-run `./update_admin.sh`.


* **Error 3: Compilation Failure (`use of undeclared identifier 'IPPROTO_TCP'`)**
* **The Cause:** The C compiler cannot find the Linux networking dictionary.
* **The Fix:** Ensure `#include <linux/in.h>` and `#include <linux/tcp.h>` are declared at the very top of `bpf/probe.c`.


## ⚖️ License & Commercial Baseline (AGPL-3.0)

Realm adopts the strictest open-source license: **GNU AGPL v3.0**.

We welcome all geeks, researchers, and enterprises to download, use, and modify Realm to build their internal defenses. However, we draw a definitive hard line for cloud vendors attempting to free-ride on open-source efforts:

**If you intend to package Realm into your commercial SaaS product, or provide Realm-based network protection services to third parties over a network, you MUST completely open-source your project and visibly retain the original author's copyright and attribution.**

You may inherit our framework, but you must respect the open-source contract.

---
