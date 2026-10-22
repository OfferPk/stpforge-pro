/**
 * STPForge Pro - IEEE 802.1w (RSTP) & IEEE 802.1s (MSTP) Protocol Engine
 * Models BPDU Binary Frames, Flag Octets, Bridge Identifiers, and L2 Convergence.
 * Compatible with Node.js and Browser environments.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.STPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Standard Spanning Tree Multicast MAC
  const STP_MULTICAST_MAC = '01:80:c2:00:00:00';

  // Standard Port Roles (IEEE 802.1w Bits 3-2)
  const PORT_ROLES = {
    0: { name: 'Unknown', code: '00' },
    1: { name: 'Alternate / Backup (Discarding)', code: '01' },
    2: { name: 'Root Port', code: '10' },
    3: { name: 'Designated Port', code: '11' }
  };

  // Standard Link Speeds and 32-bit Path Costs (IEEE 802.1D-2004)
  const LINK_PATH_COSTS = {
    '100G': { name: '100 Gbps QSFP28', cost: 200 },
    '40G':  { name: '40 Gbps QSFP+',   cost: 500 },
    '25G':  { name: '25 Gbps SFP28',   cost: 800 },
    '10G':  { name: '10 Gbps SFP+',    cost: 2000 },
    '1G':   { name: '1 Gbps 1000BASE-T', cost: 20000 },
    '100M': { name: '100 Mbps FastEthernet', cost: 200000 }
  };

  // Helper: Parse MAC string to array of 6 bytes
  function parseMac(macStr) {
    const cleaned = (macStr || '00:00:00:00:00:00').replace(/[:-]/g, '');
    const bytes = [];
    for (let i = 0; i < 12; i += 2) {
      bytes.push(parseInt(cleaned.substr(i, 2), 16) || 0);
    }
    while (bytes.length < 6) bytes.push(0);
    return bytes.slice(0, 6);
  }

  // Helper: Convert ASCII string to byte array
  function asciiToBytes(str, fixedLen) {
    const bytes = [];
    const len = fixedLen || str.length;
    for (let i = 0; i < len; i++) {
      if (i < str.length) {
        bytes.push(str.charCodeAt(i) & 0xff);
      } else {
        bytes.push(0x00);
      }
    }
    return bytes;
  }

  // Construct 8-byte Bridge / Root Identifier
  function buildBridgeId(priority, sysIdExt, macStr) {
    const prioValue = parseInt(priority, 10) || 32768; // Steps of 4096 (0, 4096, 8192 ... 61440)
    const vlanExt = parseInt(sysIdExt, 10) || 1; // 0 to 4095
    const prioField = ((prioValue & 0xf000) | (vlanExt & 0x0fff));
    const macBytes = parseMac(macStr);
    return [
      (prioField >> 8) & 0xff,
      prioField & 0xff,
      ...macBytes
    ];
  }

  // Construct 2-byte Port Identifier
  function buildPortId(portPriority, portNum) {
    const prio = parseInt(portPriority, 10) || 128; // Steps of 16 (0 to 240)
    const num = parseInt(portNum, 10) || 1; // 1 to 4095
    const portField = ((prio & 0xf0) << 8) | (num & 0x0fff);
    return [(portField >> 8) & 0xff, portField & 0xff];
  }

  // Construct 1-byte 802.1w BPDU Flags Byte
  function buildFlagsByte(cfg) {
    let flags = 0;
    if (cfg.flagTca) flags |= 0x80; // Bit 7: TCA
    if (cfg.flagAgreement) flags |= 0x40; // Bit 6: Agreement
    if (cfg.flagForwarding) flags |= 0x20; // Bit 5: Forwarding
    if (cfg.flagLearning) flags |= 0x10; // Bit 4: Learning

    const role = parseInt(cfg.portRole, 10) || 3; // Bit 3-2: 3 = Designated (11)
    flags |= ((role & 0x03) << 2);

    if (cfg.flagProposal) flags |= 0x02; // Bit 1: Proposal
    if (cfg.flagTc) flags |= 0x01; // Bit 0: Topology Change
    return flags;
  }

  // Encode IEEE 802.1w (RSTP) or IEEE 802.1s (MSTP) BPDU Frame
  function encodeBPDU(config) {
    const cfg = config || {};
    const dstMac = parseMac(STP_MULTICAST_MAC);
    const srcMac = parseMac(cfg.srcMac || '00:1a:2b:3c:4d:5e');

    const isMstp = cfg.protocolMode === 'MSTP';
    const isLegacyStp = cfg.protocolMode === 'STP_8021D';

    const protoVer = isMstp ? 0x03 : (isLegacyStp ? 0x00 : 0x02); // 2=RSTP, 3=MSTP
    const bpduType = isLegacyStp ? 0x00 : 0x02; // 0=Config, 2=RSTP/MSTP

    // LLC Header: DSAP 0x42, SSAP 0x42, Control 0x03
    const llcHeader = [0x42, 0x42, 0x03];

    // STP Base Header
    const stpBase = [];
    stpBase.push(0x00, 0x00); // Protocol Identifier: 0x0000
    stpBase.push(protoVer);   // Protocol Version: 0x02 (RSTP)
    stpBase.push(bpduType);   // BPDU Type: 0x02 (RST / MST)

    // Flags
    const flagsByte = buildFlagsByte(cfg);
    stpBase.push(flagsByte);

    // Root Identifier (8 bytes)
    const rootId = buildBridgeId(cfg.rootPriority || 0, cfg.vlanId || 1, cfg.rootMac || '00:01:02:03:04:05');
    stpBase.push(...rootId);

    // Root Path Cost (4 bytes)
    const pathCost = parseInt(cfg.rootPathCost, 10) || 2000;
    stpBase.push(
      (pathCost >> 24) & 0xff,
      (pathCost >> 16) & 0xff,
      (pathCost >> 8) & 0xff,
      pathCost & 0xff
    );

    // Bridge Identifier (8 bytes)
    const bridgeId = buildBridgeId(cfg.bridgePriority || 32768, cfg.vlanId || 1, cfg.srcMac || '00:1a:2b:3c:4d:5e');
    stpBase.push(...bridgeId);

    // Port Identifier (2 bytes)
    const portId = buildPortId(cfg.portPriority || 128, cfg.portNumber || 1);
    stpBase.push(...portId);

    // Timers (2 bytes each in 1/256 seconds)
    const msgAgeSec = parseFloat(cfg.messageAge) || 0.0;
    const maxAgeSec = parseFloat(cfg.maxAge) || 20.0;
    const helloSec = parseFloat(cfg.helloTime) || 2.0;
    const fwdDelaySec = parseFloat(cfg.forwardDelay) || 15.0;

    const msgAgeVal = Math.round(msgAgeSec * 256);
    const maxAgeVal = Math.round(maxAgeSec * 256);
    const helloVal = Math.round(helloSec * 256);
    const fwdDelayVal = Math.round(fwdDelaySec * 256);

    stpBase.push((msgAgeVal >> 8) & 0xff, msgAgeVal & 0xff);
    stpBase.push((maxAgeVal >> 8) & 0xff, maxAgeVal & 0xff);
    stpBase.push((helloVal >> 8) & 0xff, helloVal & 0xff);
    stpBase.push((fwdDelayVal >> 8) & 0xff, fwdDelayVal & 0xff);

    // RSTP Extension: Version 1 Length (1 byte: 0x00)
    let stpExtensions = [];
    if (!isLegacyStp) {
      stpExtensions.push(0x00); // Version 1 Length
    }

    // MSTP Version 3 Extension (IEEE 802.1s)
    if (isMstp) {
      const mstRegionName = asciiToBytes(cfg.mstRegionName || 'CORP-FABRIC-01', 32);
      const mstRev = parseInt(cfg.mstRevision, 10) || 1;
      const mstDigest = [
        0xac, 0x36, 0x17, 0x7f, 0x50, 0x28, 0x3c, 0xd4,
        0xb8, 0x95, 0xcc, 0x01, 0x22, 0x64, 0x5a, 0x1f
      ]; // Simulated 16-byte MD5 configuration digest
      const cistInternalCost = parseInt(cfg.cistInternalCost, 10) || 0;
      const cistBridgeId = bridgeId;
      const remainingHops = parseInt(cfg.cistRemainingHops, 10) || 20;

      const v3Payload = [
        0x00, // Format selector (0x00)
        ...mstRegionName,
        (mstRev >> 8) & 0xff, mstRev & 0xff,
        ...mstDigest,
        (cistInternalCost >> 24) & 0xff, (cistInternalCost >> 16) & 0xff,
        (cistInternalCost >> 8) & 0xff, cistInternalCost & 0xff,
        ...cistBridgeId,
        remainingHops
      ];

      const v3Len = v3Payload.length;
      stpExtensions.push((v3Len >> 8) & 0xff, v3Len & 0xff, ...v3Payload);
    }

    const payload = [...llcHeader, ...stpBase, ...stpExtensions];
    const ethLen = payload.length;
    const ethLenBytes = [(ethLen >> 8) & 0xff, ethLen & 0xff];

    const fullFrame = [...dstMac, ...srcMac, ...ethLenBytes, ...payload];

    return {
      frameBytes: fullFrame,
      totalLength: fullFrame.length,
      payloadLength: payload.length,
      hexString: fullFrame.map(b => b.toString(16).padStart(2, '0')).join('')
    };
  }

  // Format Frame to Wireshark-Style Hex Dump
  function formatHexDump(bytes) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(4, '0');
      const hexPart = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
      const paddedHex = hexPart.padEnd(48, ' ');
      const asciiPart = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
      lines.push(`${offset}   ${paddedHex}   |${asciiPart}|`);
    }
    return lines.join('\n');
  }

  // STP Convergence & Timer Dimensioning Engine
  function calculateConvergence(params) {
    const mode = params.protocolMode || 'RSTP';
    const isPortFast = !!params.portFastEnabled;
    const fwdDelay = parseFloat(params.forwardDelay) || 15.0;
    const maxAge = parseFloat(params.maxAge) || 20.0;
    const diameter = parseInt(params.networkDiameter, 10) || 7;

    let convergenceTimeSec = 0;
    let convergenceDesc = '';

    if (isPortFast) {
      convergenceTimeSec = 0.0;
      convergenceDesc = 'Instantaneous (0 seconds) via PortFast / Edge Port. Bypasses Listening/Learning.';
    } else if (mode === 'RSTP' || mode === 'MSTP') {
      convergenceTimeSec = 0.8;
      convergenceDesc = 'Sub-second (<1.0s) via Rapid Proposal/Agreement synchronization handshake.';
    } else {
      // Legacy 802.1D STP
      convergenceTimeSec = (2 * fwdDelay) + maxAge; // 15 + 15 + 20 = 50 seconds
      convergenceDesc = `Legacy 802.1D Timer-driven: 50.0s (Listening 15s + Learning 15s + Max Age ${maxAge}s).`;
    }

    // Recommended Max Age based on Network Diameter
    const recommendedMaxAge = Math.min(40, Math.max(6, 2 * (fwdDelay - 1)));
    const macAgingTcSec = fwdDelay; // MAC aging drops to 15s during Topology Change

    return {
      mode,
      convergenceTimeSec: convergenceTimeSec.toFixed(1),
      convergenceDesc,
      diameter,
      recommendedMaxAge,
      macAgingTcSec
    };
  }

  return {
    STP_MULTICAST_MAC,
    PORT_ROLES,
    LINK_PATH_COSTS,
    buildBridgeId,
    buildPortId,
    buildFlagsByte,
    encodeBPDU,
    formatHexDump,
    calculateConvergence
  };
}));
