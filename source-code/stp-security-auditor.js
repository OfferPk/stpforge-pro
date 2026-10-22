/**
 * STPForge Pro - 10-Point Zero-Trust Spanning Tree Security Auditor
 * Evaluates IEEE 802.1w (RSTP) & IEEE 802.1s (MSTP) against BPDU injection,
 * Root Bridge hijacking, and broadcast loop vulnerabilities.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.STPSecurityAuditor = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function auditSTPSecurity(cfg) {
    const findings = [];
    let totalScore = 0;

    // Check 1: Access Port BPDU Guard & Edge Port Enforcement (12 pts)
    if (cfg.bpduGuardEnabled) {
      findings.push({
        id: 'BPDU_GUARD',
        name: 'Access Port BPDU Guard & PortFast Enforcement',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'BPDU Guard enabled globally or per-interface on all edge access ports. Any received BPDU immediately err-disables the port, preventing rogue switches or hypervisors from joining the topology.',
        remediation: null
      });
      totalScore += 12;
    } else {
      findings.push({
        id: 'BPDU_GUARD',
        name: 'Access Port BPDU Guard & PortFast Enforcement',
        score: 0,
        maxScore: 12,
        status: 'FAIL',
        description: 'CRITICAL VULNERABILITY: BPDU Guard disabled on access ports! Any rogue laptop or virtual machine can inject forged BPDUs, claim root bridge priority, or cause network-wide broadcast loops.',
        remediation: 'Configure "spanning-tree portfast bpduguard default" or enable BPDU block on all edge ports.'
      });
    }

    // Check 2: Core Root Bridge Priority & Root Guard Hardening (12 pts)
    const isRootPrioSecure = (parseInt(cfg.rootPriority, 10) === 0 || parseInt(cfg.rootPriority, 10) === 4096);
    if (cfg.rootGuardEnabled && isRootPrioSecure) {
      findings.push({
        id: 'ROOT_GUARD',
        name: 'Deterministic Root Priority & Root Guard Hardening',
        score: 12,
        maxScore: 12,
        status: 'PASS',
        description: 'Core switches configured with deterministic low priority (0/4096) and downstream links protected with Root Guard (spanning-tree guard root). Root Bridge position is immutable.',
        remediation: null
      });
      totalScore += 12;
    } else if (cfg.rootGuardEnabled || isRootPrioSecure) {
      findings.push({
        id: 'ROOT_GUARD',
        name: 'Deterministic Root Priority & Root Guard Hardening',
        score: 6,
        maxScore: 12,
        status: 'WARN',
        description: 'Partial root protection. Either Root Guard is missing on downstream distribution ports, or Bridge Priority is left at default 32768, risking election instability.',
        remediation: 'Set primary core priority to 0 (or 4096) and configure "spanning-tree guard root" on all non-root uplinks.'
      });
      totalScore += 6;
    } else {
      findings.push({
        id: 'ROOT_GUARD',
        name: 'Deterministic Root Priority & Root Guard Hardening',
        score: 0,
        maxScore: 12,
        status: 'FAIL',
        description: 'CRITICAL HAZARD: Default bridge priority 32768 and zero Root Guard protection! A newly connected access switch with lower MAC address will hijack the Root Bridge.',
        remediation: 'Assign explicit root priority (0 for Primary, 4096 for Secondary) and enable Root Guard on downstream ports.'
      });
    }

    // Check 3: Rapid STP (802.1w) / MSTP (802.1s) Migration (10 pts)
    if (cfg.protocolMode === 'RSTP' || cfg.protocolMode === 'MSTP') {
      findings.push({
        id: 'PROTOCOL_VERSION',
        name: 'Modern Spanning Tree Standard (RSTP / MSTP)',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Modern IEEE 802.1w Rapid STP or IEEE 802.1s Multiple Spanning Tree active. Provides sub-second convergence (<1s) via Proposal/Agreement handshake.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'PROTOCOL_VERSION',
        name: 'Modern Spanning Tree Standard (RSTP / MSTP)',
        score: 0,
        maxScore: 10,
        status: 'FAIL',
        description: 'CRITICAL OUTAGE RISK: Legacy IEEE 802.1D Spanning Tree detected! 30-to-50 second convergence delay causes severe application timeouts during link reconvergence.',
        remediation: 'Migrate switch spanning-tree mode to "rapid-pvst" or "mst".'
      });
    }

    // Check 4: Loop Guard & Unidirectional Link Detection (UDLD) (10 pts)
    if (cfg.loopGuardEnabled) {
      findings.push({
        id: 'LOOP_GUARD',
        name: 'Loop Guard & Unidirectional Link Failure Protection',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Loop Guard enabled on point-to-point fiber uplinks. Prevents alternate or root ports from transitioning to designated forwarding if BPDUs cease due to unidirectional fiber cuts.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'LOOP_GUARD',
        name: 'Loop Guard & Unidirectional Link Failure Protection',
        score: 2,
        maxScore: 10,
        status: 'FAIL',
        description: 'Loop Guard disabled! Unidirectional fiber faults (where Tx fails but Rx remains up) will cause blocked ports to transition to forwarding, triggering a catastrophic bridging loop.',
        remediation: 'Enable "spanning-tree loopguard default" globally and configure aggressive UDLD on fiber links.'
      });
      totalScore += 2;
    }

    // Check 5: Topology Change (TC) Rate-Limiting & MAC Flap Damping (10 pts)
    if (cfg.tcDampingEnabled) {
      findings.push({
        id: 'TC_DAMPING',
        name: 'Topology Change (TC) Rate-Limiting & MAC Flap Damping',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Topology Change notification dampening active. Suppresses rapid TC storms caused by flapping end-user ports, preventing network-wide MAC address table flushes.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'TC_DAMPING',
        name: 'Topology Change (TC) Rate-Limiting & MAC Flap Damping',
        score: 3,
        maxScore: 10,
        status: 'WARN',
        description: 'Unthrottled TC notifications. A single flapping PC or printer will broadcast TC BPDUs continuously, reducing MAC table aging from 300s to 15s and flooding unicast frames across the LAN.',
        remediation: 'Ensure all edge ports have PortFast enabled to suppress TC generation on link state changes.'
      });
      totalScore += 3;
    }

    // Check 6: MSTP Region & VLAN-to-Instance Digest Alignment (10 pts)
    if (cfg.protocolMode === 'MSTP') {
      if (cfg.mstDigestAligned) {
        findings.push({
          id: 'MST_ALIGNMENT',
          name: 'MSTP Region & VLAN-to-Instance Digest Consistency',
          score: 10,
          maxScore: 10,
          status: 'PASS',
          description: 'MST Configuration Name, Revision Level, and 16-byte MD5 VLAN-to-Instance digest aligned across all fabric nodes. CIST and MSTI instances operate seamlessly.',
          remediation: null
        });
        totalScore += 10;
      } else {
        findings.push({
          id: 'MST_ALIGNMENT',
          name: 'MSTP Region & VLAN-to-Instance Digest Consistency',
          score: 2,
          maxScore: 10,
          status: 'FAIL',
          description: 'MSTP Region Digest Mismatch! Switches treat each other as boundary bridges, collapsing all instances into a single CIST hop and losing multi-instance load balancing.',
          remediation: 'Standardize MST Region Name, Revision, and VLAN mapping across all switches.'
        });
        totalScore += 2;
      }
    } else {
      // Rapid-PVST / RSTP mode: Full score if VLAN mapping is consistent
      findings.push({
        id: 'MST_ALIGNMENT',
        name: 'Per-VLAN Spanning Tree Instance Consistency',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'Per-VLAN Rapid Spanning Tree (PVRST+) active with isolated spanning-tree topology per VLAN broadcast domain.',
        remediation: null
      });
      totalScore += 10;
    }

    // Check 7: External Border & Transit Uplink BPDU Filtering (10 pts)
    if (cfg.borderBpduFilter) {
      findings.push({
        id: 'BORDER_BPDU_FILTER',
        name: 'External Border & Peering BPDU Boundary Isolation',
        score: 10,
        maxScore: 10,
        status: 'PASS',
        description: 'BPDU filtering or drop-rules active on external carrier, WAN handoffs, or customer transit links. Prevents external Spanning Tree topologies from interacting with internal core.',
        remediation: null
      });
      totalScore += 10;
    } else {
      findings.push({
        id: 'BORDER_BPDU_FILTER',
        name: 'External Border & Peering BPDU Boundary Isolation',
        score: 0,
        maxScore: 10,
        status: 'FAIL',
        description: 'CRITICAL BOUNDARY LEAK: BPDUs transmitted across external service provider or customer uplinks! Outside Spanning Tree topologies can disrupt internal root elections.',
        remediation: 'Configure "spanning-tree bpdufilter enable" on external customer and carrier handoff interfaces.'
      });
    }

    // Check 8: Point-to-Point Link Type Validation (9 pts)
    if (cfg.p2pLinkType) {
      findings.push({
        id: 'P2P_LINK_TYPE',
        name: 'Point-to-Point Full-Duplex Link Handshake Verification',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'All inter-switch links verified as full-duplex point-to-point (P2P). Enables rapid Proposal/Agreement synchronization without waiting for forward delay timers.',
        remediation: null
      });
      totalScore += 9;
    } else {
      findings.push({
        id: 'P2P_LINK_TYPE',
        name: 'Point-to-Point Full-Duplex Link Handshake Verification',
        score: 4,
        maxScore: 9,
        status: 'WARN',
        description: 'Inter-switch links operating in shared half-duplex mode or link-type auto. Forces RSTP to fall back to legacy 802.1D timers (30-50s) instead of rapid handshakes.',
        remediation: 'Enforce full-duplex or configure "spanning-tree link-type point-to-point" on all switch-to-switch trunks.'
      });
      totalScore += 4;
    }

    // Check 9: Control Plane Policing (CoPP) for BPDU Multicast MAC (9 pts)
    if (cfg.coppBpduProtection) {
      findings.push({
        id: 'COPP_BPDU',
        name: 'Control Plane Policing (CoPP) for 01:80:C2:00:00:00',
        score: 9,
        maxScore: 9,
        status: 'PASS',
        description: 'Hardware rate-limiting active on Spanning Tree multicast MAC 01:80:C2:00:00:00. Protects switch CPU from high-volume BPDU denial-of-service floods.',
        remediation: null
      });
      totalScore += 9;
    } else {
      findings.push({
        id: 'COPP_BPDU',
        name: 'Control Plane Policing (CoPP) for 01:80:C2:00:00:00',
        score: 0,
        maxScore: 9,
        status: 'FAIL',
        description: 'No CoPP rate-limiting for BPDU traffic! An attacker flooding thousands of forged BPDUs per second will starve switch CPU resources and cause neighbor dead-timer drops.',
        remediation: 'Apply CoPP policy policing Spanning Tree BPDUs to <= 200 pps.'
      });
    }

    // Check 10: Max Age & Hello Timer Convergence Tuning (8 pts)
    const hello = parseFloat(cfg.helloTime) || 2.0;
    const maxAge = parseFloat(cfg.maxAge) || 20.0;
    const fwdDelay = parseFloat(cfg.forwardDelay) || 15.0;
    const isTimerValid = (2 * (fwdDelay - 1) >= maxAge) && (maxAge >= 2 * (hello + 1));

    if (isTimerValid) {
      findings.push({
        id: 'TIMER_TUNING',
        name: 'Spanning Tree Timer & Network Diameter Synchronization',
        score: 8,
        maxScore: 8,
        status: 'PASS',
        description: `Timers mathematically validated (Hello: ${hello}s, MaxAge: ${maxAge}s, Forward Delay: ${fwdDelay}s). Complies with IEEE 802.1D diameter constraints.`,
        remediation: null
      });
      totalScore += 8;
    } else {
      findings.push({
        id: 'TIMER_TUNING',
        name: 'Spanning Tree Timer & Network Diameter Synchronization',
        score: 3,
        maxScore: 8,
        status: 'WARN',
        description: 'Suboptimal Spanning Tree timer relationships. May cause premature timeouts or false link failure declarations across large network diameters.',
        remediation: 'Ensure 2 * (Forward_Delay - 1) >= Max_Age and Max_Age >= 2 * (Hello + 1).'
      });
      totalScore += 3;
    }

    // Grading Scale
    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 60) grade = 'D';

    const passed = totalScore >= 80;
    let summary = '';
    if (grade === 'A+' || grade === 'A') {
      summary = 'Carrier-grade Zero-Trust Spanning Tree architecture with edge BPDU Guard, deterministic Core Root Bridge protection, Loop Guard, and CoPP rate-limiting.';
    } else if (grade === 'B') {
      summary = 'Acceptable operational baseline, but minor gaps exist in timer synchronization, TC damping, or link-type validation.';
    } else {
      summary = 'Critical Layer 2 outage hazard! Missing BPDU Guard on access ports or default bridge priority invites Root Bridge hijacking and catastrophic broadcast storms.';
    }

    return {
      totalScore,
      maxScore: 100,
      grade,
      passed,
      summary,
      findings
    };
  }

  return {
    auditSTPSecurity
  };
}));
