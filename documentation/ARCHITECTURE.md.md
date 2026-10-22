# STPForge Pro v1.0.0 — Architecture & Engineering Manual

## 1\. Executive Summary: The Layer 2 Loop-Prevention Backbone

The **Rapid Spanning Tree Protocol (RSTP \- IEEE 802.1w)** and **Multiple Spanning Tree Protocol (MSTP \- IEEE 802.1s)** provide the core loop-prevention and rapid Layer 2 failover mechanisms across global campus networks, enterprise LANs, and data center fabrics:

1. **Active Topology Calculation**: Creates a single, loop-free spanning tree topology across physical redundant links while keeping redundant paths in an alternate (discarding/blocking) state.  
2. **Sub-Second Convergence**: Replaces legacy IEEE 802.1D timer-driven convergence (30–50 seconds) with explicit, point-to-point **Proposal / Agreement handshakes** that converge in under 1 second.  
3. **Multi-Instance Traffic Engineering (MSTP)**: Maps hundreds of individual VLANs into a small set of Multiple Spanning Tree Instances (MSTIs) to achieve load-balanced Layer 2 paths without CPU overhead.

                  \+---------------------------+

                  |  Primary Root Bridge (0)  |

                  |     MAC: 00:01:02:03:04   |

                  \+---------------------------+

                         /             \\

      Root Port (10)   /                 \\  Root Port (10)

                     /                     \\

       \+-----------------------+     \+-----------------------+

       | Distribution Switch 1 |=====| Distribution Switch 2 |

       |     Priority: 4096    |     |     Priority: 8192    |

       \+-----------------------+     \+-----------------------+

                   |                             |

      Designated   |                             | Alternate (Blocked)

                   |                             | \[Loop Prevention\]

       \+-----------------------+                 |

       |  Access Switch Edge   |-----------------+

       | (BPDU Guard / PortFast)

       \+-----------------------+

---

## 2\. Protocol Specification & BPDU Wireframe Structures

### 2.1 Ethernet & LLC Encapsulation

- **Destination Multicast MAC**: `01:80:C2:00:00:00` (Spanning Tree Block Multicast).  
- **LLC Header (3 bytes)**:  
  - DSAP: `0x42` (Bridge Spanning Tree Protocol)  
  - SSAP: `0x42`  
  - Control: `0x03` (Unnumbered Information)  
- **Protocol Identifier (2 bytes)**: `0x0000` (IEEE 802.1D/w/s).  
- **Protocol Version (1 byte)**:  
  - `0x00`: IEEE 802.1D Legacy STP  
  - `0x02`: IEEE 802.1w Rapid Spanning Tree Protocol (RSTP)  
  - `0x03`: IEEE 802.1s Multiple Spanning Tree Protocol (MSTP)  
- **BPDU Type (1 byte)**:  
  - `0x00`: Configuration BPDU (802.1D)  
  - `0x02`: Rapid / Multiple Spanning Tree BPDU (RSTP / MSTP)  
  - `0x80`: Topology Change Notification (TCN BPDU)

### 2.2 IEEE 802.1w BPDU Flags Byte

Packed as an 8-bit octet:

- **Bit 7 (TCA)**: Topology Change Acknowledgment  
- **Bit 6 (Agreement)**: Confirms transition to Designated Forwarding  
- **Bit 5 (Forwarding)**: Port is in Forwarding state  
- **Bit 4 (Learning)**: Port is in Learning state  
- **Bits 3-2 (Port Role)**:  
  - `00`: Unknown  
  - `01`: Alternate / Backup Port (Discarding)  
  - `10`: Root Port  
  - `11`: Designated Port  
- **Bit 1 (Proposal)**: Rapid convergence handshake request  
- **Bit 0 (TC)**: Topology Change flag

### 2.3 Bridge & Port Identifiers

- **Bridge Identifier (8 bytes)**:  
  - Priority: 4 bits (0 to 61440 in increments of 4096\)  
  - System ID Extension: 12 bits (VLAN ID 0–4095 or MST Instance)  
  - MAC Address: 6 bytes (Base switch chassis MAC)  
- **Port Identifier (2 bytes)**:  
  - Port Priority: 4 bits (0 to 240 in steps of 16, default 128\)  
  - Port Number: 12 bits (1 to 4095\)

---

## 3\. Operational Headaches & Catastrophic L2 Failures

1. **Rogue Root Bridge Hijacking**:  
   - When default bridge priority (32768) is used throughout a network, any user or attacker plugging a laptop with an open-source bridge (or virtual switch) advertising Priority 0 becomes the **Root Bridge** for the entire enterprise. Traffic redirects through the laptop, causing massive packet capture and network collapse.  
   - *Mitigation*: Assign priority 0 to primary core, 4096 to secondary, and configure **Root Guard** on all downstream distribution ports.  
2. **Bridging Loops & Broadcast Storms**:  
   - A single physical loop or unidirectional link failure (where transmit fiber fails but receive continues) can cause blocked ports to transition to forwarding. Broadcast packets circulate infinitely at line-rate, pinning switch CPUs to 100% and taking down the entire enterprise in seconds.  
   - *Mitigation*: Deploy **BPDU Guard** on all access ports, **Loop Guard** on all fiber trunks, and enable UDLD.  
3. **Topology Change (TC) Storms & MAC Flapping**:  
   - Every time an unhardened access port links up or down, a Topology Change BPDU is flooded throughout the network. Every switch flushes its MAC address table (aging timer reduced from 300s to 15s), flooding all unicast traffic as unknown unicast broadcasts.  
   - *Mitigation*: Enforce **PortFast / Edge Port** on all access ports to completely suppress TC generation on edge state changes.  
4. **MSTP Region Boundary Partitioning**:  
   - If two switches differ by a single character in their MST Configuration Name, Revision, or VLAN-to-Instance mapping table, their 16-byte MD5 configuration digests mismatch. The switches treat each other as boundary bridges, collapsing all instances into a single CIST hop and eliminating load balancing.  
   - *Mitigation*: Automate MSTP configuration consistency validation.

---

## 4\. 10-Point Zero-Trust Spanning Tree Security Rubric

1. **Access Port BPDU Guard & PortFast Enforcement (12 pts)**: Disables rogue switches on edge.  
2. **Deterministic Root Priority & Root Guard Hardening (12 pts)**: Locks core root position.  
3. **Modern Spanning Tree Standard (RSTP / MSTP) (10 pts)**: Eliminates 50s legacy convergence.  
4. **Loop Guard & Unidirectional Link Failure Protection (10 pts)**: Blocks fiber loop faults.  
5. **Topology Change (TC) Rate-Limiting & MAC Flap Damping (10 pts)**: Prevents MAC table thrashing.  
6. **MSTP Region & VLAN-to-Instance Digest Consistency (10 pts)**: Ensures multi-instance alignment.  
7. **External Border & Peering BPDU Boundary Isolation (10 pts)**: Isolates WAN and provider links.  
8. **Point-to-Point Full-Duplex Link Handshake Verification (9 pts)**: Enforces sub-second P2P handshakes.  
9. **Control Plane Policing (CoPP) for 01:80:C2:00:00:00 (9 pts)**: Throttles BPDU CPU flood attacks.  
10. **Spanning Tree Timer & Network Diameter Synchronization (8 pts)**: Aligns diameter and max-age timers.