

STP

# 

STPForge Pro

IEEE 802.1w (RSTP) & IEEE 802.1s (MSTP) Zero-Trust Loop-Prevention & Convergence Studio  
IEEE 802.1w RSTP IEEE 802.1s MSTP BPDU GUARD ROOT GUARD SUB-SECOND L2  
Hardened Enterprise Core (Grade A+) Campus Access Edge with MSTP (Grade A) Vulnerable Unhardened LAN (Grade F) Synthesize & Re-Audit

Bridge & Root Identifiers IEEE 802.1w RSTP

Protocol Mode IEEE 802.1w Rapid STP (RSTP) IEEE 802.1s Multiple STP (MSTP) Legacy IEEE 802.1D STP (Slow 50s)  
VLAN ID / SysID Ext

Root Bridge Priority 0 (Primary Root Bridge) 4096 (Secondary Root Bridge) 8192 (Tertiary Backup) 32768 (Default Unhardened) 61440 (Lowest Priority)  
Local Bridge Priority 0 (Root) 4096 (Secondary) 8192 (Distribution) 32768 (Access Switch)

Root Bridge MAC  
Local Switch MAC

Link Speed & 32-bit Path Cost 100 Gbps QSFP28 (Cost: 200\) 40 Gbps QSFP+ (Cost: 500\) 25 Gbps SFP28 (Cost: 800\) 10 Gbps SFP+ (Cost: 2,000) 1 Gbps 1000BASE-T (Cost: 20,000)  
Port Role (Bits 3-2) Designated Port (11) Root Port (10) Alternate / Backup (01)

Port Number  
Port Priority

STP Timers & MSTP Region Validated

Hello Time (Seconds)  
Forward Delay (Seconds)

Max Age (Seconds)  
Max Network Diameter

MST Region Name (IEEE 802.1s)  
MST Revision

10-Point Zero-Trust Spanning Tree Controls  
Access Port BPDU Guard (Err-Disable Rogue Switches on Edge)  
Root Guard (spanning-tree guard root on Distribution Facing Links)  
Loop Guard (Prevent Unidirectional Fiber Bridging Loops)  
Topology Change Damping (Suppress Flapping Edge MAC Flushes)  
MSTP Region Digest Alignment (CIST & MSTI Synchronized)  
External Border BPDU Filtering (Isolate Provider / WAN Handoffs)  
Point-to-Point Full-Duplex Link Type (Enable Rapid Handshake)  
CoPP Rate-Limiting for Multicast MAC 01:80:C2:00:00:00 (200 pps)  
PortFast / Edge Port Enabled (Bypass 30s Listening/Learning)

Spanning Tree Telemetry & Convergence Metrics

\< 1.0s  
Convergence Time

52 Bytes  
BPDU Frame Size

7 Hops  
Max Diameter

15 Sec  
TC MAC Aging

10-Point Zero-Trust Spanning Tree Security Scorecard

A+

### **100 / 100 Points (Passed)**

Carrier-grade Zero-Trust Spanning Tree architecture with edge BPDU Guard, deterministic Core Root Bridge protection, Loop Guard, and CoPP rate-limiting.

IEEE 802.1w & IEEE 802.1s Binary BPDU Hex Dissector 52 Bytes BPDU Frame  
Loading BPDU wireframe...

Multi-Platform Switch Synthesizer Copy Config  
Cisco IOS-XE / NX-OS Arista EOS Juniper Junos Linux (mstpd) Prometheus Alerts  
Generating switch configuration...