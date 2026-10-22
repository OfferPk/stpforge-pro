# STPForge Pro v1.0.0 — User Guide & NetDevOps Manual

## 1\. Web Studio Quickstart

1. Open `source-code/index.html` in any modern web browser.  
2. Select an industry preset from the top bar:  
   - **Hardened Enterprise Core**: Root Priority 0, Root Guard active, BPDU Guard active, Loop Guard active, RSTP mode, P2P link type, CoPP enabled, and TC damping active (Grade A+).  
   - **Campus Access Edge with MSTP**: MSTP mode (IEEE 802.1s), Region CORP-FABRIC-01, Revision 1, BPDU Guard on all access ports, PortFast enabled, and Root Guard on uplinks (Grade A).  
   - **Vulnerable Unhardened LAN**: Default Bridge Priority 32768, BPDU Guard disabled, Root Guard disabled, Legacy 802.1D STP mode, shared half-duplex links, no CoPP, and unthrottled TC storms (Grade F).  
3. Review the **Spanning Tree Telemetry & Convergence Metrics**:  
   - Model protocol convergence time (\<1.0s in RSTP vs 50.0s in legacy STP vs 0.0s in PortFast), BPDU frame size, maximum network diameter, and MAC aging during Topology Change.  
4. Review the **10-Point Zero-Trust Spanning Tree Security Scorecard**:  
   - Check compliance across BPDU Guard, Root Guard, Loop Guard, TC damping, MST digest consistency, and CoPP rate-limiting.  
5. Review the **IEEE 802.1w & IEEE 802.1s Binary BPDU Hex Dissector**:  
   - Inspect the Wireshark-style hex dump with decoded flags, Root ID, Bridge ID, Port ID, and timers.  
6. Export synthesized production configurations for **Cisco IOS-XE / NX-OS**, **Arista EOS**, **Juniper Junos**, **Linux (mstpd)**, and **Prometheus Alert Rules**.

---

## 2\. DevSecOps CLI Tool (`stpforge-cli.py`)

The standalone Python CLI runs on Python 3.8+ with zero external dependencies.

### 2.1 Encoding IEEE 802.1w (RSTP) & 802.1s (MSTP) BPDU Frames

\# Encode RSTP BPDU Frame

python3 build/stpforge-cli.py encode \\

  \--mode RSTP \\

  \--root-prio 0 \\

  \--cost 2000

\# Encode MSTP BPDU Frame with Region Configuration

python3 build/stpforge-cli.py encode \\

  \--mode MSTP \\

  \--root-prio 4096 \\

  \--cost 500

Output:

\=== IEEE 802.1w/802.1s BPDU Frame Encoded (53 Bytes) \===

0000   01 80 c2 00 00 00 00 1a 2b 3c 4d 5e 00 27 42 42    |........+\<M^.'BB|

0010   03 00 00 02 02 7c 00 64 00 01 02 03 04 05 00 00    |.....|.d........|

0020   07 d0 80 64 00 1a 2b 3c 4d 5e 80 01 00 00 14 00    |...d..+\<M^......|

0030   02 00 0f 00 00                                     |.....|

### 2.2 Analyzing STP Convergence & Timer Equations

python3 build/stpforge-cli.py timer-calc \\

  \--diameter 7 \\

  \--hello 2.0 \\

  \--fwd-delay 15.0 \\

  \--max-age 20.0

Output:

\=== Spanning Tree Convergence & Diameter Analysis (Diameter: 7\) \===

Rapid STP (802.1w) Convergence: \< 1.0s (Sub-second Proposal/Agreement handshake)

PortFast Edge Convergence:     0.0s (Direct Forwarding, zero TC notifications)

Legacy 802.1D STP Convergence: 50.0s (2\*FwdDelay 30.0s \+ MaxAge 20.0s)

MAC Aging during TC:          15.0s (Flushed from default 300s)

Timer Equation Validity:       VALID (IEEE Compliant)

### 2.3 Generating Wireshark PCAP Capture Files

python3 build/stpforge-cli.py pcap-dump \-o bpdu\_frame.pcap

Generates a standard `.pcap` capture file ready to open in Wireshark or tcpdump.

### 2.4 Running Zero-Trust CI/CD Audits

\# Validating production Hardened Core configuration (Exits code 0\)

python3 build/stpforge-cli.py audit \-c build/presets/hardened-enterprise-core.json \--strict

\# Validating vulnerable LAN configuration (Exits code 1\)

python3 build/stpforge-cli.py audit \-c build/presets/vulnerable-unhardened-lan.json \--strict

---

## 3\. GitHub Actions CI/CD Pipeline Gate

Add this workflow to your infrastructure repository (`.github/workflows/stp-audit.yml`):

name: Spanning Tree Zero-Trust Gate

on:

  pull\_request:

    paths:

      \- 'switch-configs/\*\*'

      \- 'ansible/roles/stp/\*\*'

      \- 'layer2/\*\*'

jobs:

  stp-audit:

    runs-on: ubuntu-latest

    steps:

      \- name: Checkout Code

        uses: actions/checkout@v4

      \- name: Set up Python

        uses: actions/setup-python@v5

        with:

          python-version: '3.11'

      \- name: Run STPForge Strict Audit Gate

        run: |

          python3 build/stpforge-cli.py audit \-c build/presets/hardened-enterprise-core.json \--strict