/**
 * STPForge Pro - Web Application Controller
 */

(function () {
  'use strict';

  const PRESETS = {
    core: {
      name: 'Hardened Enterprise Core (Grade A+)',
      protocolMode: 'RSTP',
      vlanId: 100,
      rootPriority: 0,
      bridgePriority: 0,
      rootMac: '00:01:02:03:04:05',
      srcMac: '00:01:02:03:04:05', // This switch is the root!
      rootPathCost: 0,
      portRole: 3, // Designated Port
      portNumber: 1,
      portPriority: 128,
      helloTime: 2.0,
      forwardDelay: 15.0,
      maxAge: 20.0,
      networkDiameter: 7,
      mstRegionName: 'CORP-FABRIC-01',
      mstRevision: 1,
      bpduGuardEnabled: true,
      rootGuardEnabled: true,
      loopGuardEnabled: true,
      tcDampingEnabled: true,
      mstDigestAligned: true,
      borderBpduFilter: true,
      p2pLinkType: true,
      coppBpduProtection: true,
      portFastEnabled: true
    },
    campus: {
      name: 'Campus Access Edge with MSTP (Grade A)',
      protocolMode: 'MSTP',
      vlanId: 10,
      rootPriority: 4096,
      bridgePriority: 32768,
      rootMac: '00:01:02:03:04:05',
      srcMac: '00:22:33:44:55:66',
      rootPathCost: 2000,
      portRole: 2, // Root Port
      portNumber: 49,
      portPriority: 128,
      helloTime: 2.0,
      forwardDelay: 15.0,
      maxAge: 20.0,
      networkDiameter: 7,
      mstRegionName: 'CORP-FABRIC-01',
      mstRevision: 1,
      bpduGuardEnabled: true,
      rootGuardEnabled: true,
      loopGuardEnabled: true,
      tcDampingEnabled: true,
      mstDigestAligned: true,
      borderBpduFilter: true,
      p2pLinkType: true,
      coppBpduProtection: true,
      portFastEnabled: true
    },
    vulnerable: {
      name: 'Vulnerable Unhardened LAN (Grade F)',
      protocolMode: 'STP_8021D', // Legacy slow STP!
      vlanId: 1,
      rootPriority: 32768, // Default priority - easily hijacked!
      bridgePriority: 32768,
      rootMac: '00:99:88:77:66:55',
      srcMac: '00:11:22:33:44:55',
      rootPathCost: 20000,
      portRole: 3,
      portNumber: 1,
      portPriority: 128,
      helloTime: 2.0,
      forwardDelay: 15.0,
      maxAge: 20.0,
      networkDiameter: 7,
      mstRegionName: '',
      mstRevision: 0,
      bpduGuardEnabled: false, // Vulnerable to rogue switch injection!
      rootGuardEnabled: false, // Rogue switch can claim root!
      loopGuardEnabled: false, // Vulnerable to unidirectional loops!
      tcDampingEnabled: false, // TC storms flush MAC tables!
      mstDigestAligned: false,
      borderBpduFilter: false, // Leaks to external providers!
      p2pLinkType: false, // Half-duplex timers!
      coppBpduProtection: false, // CPU flood target!
      portFastEnabled: false // 50-second convergence delay!
    }
  };

  let activeTab = 'cisco';

  // DOM Elements
  const elProtocolMode = document.getElementById('select-protocol-mode');
  const elVlanId = document.getElementById('input-vlan-id');
  const elRootPriority = document.getElementById('select-root-priority');
  const elBridgePriority = document.getElementById('select-bridge-priority');
  const elRootMac = document.getElementById('input-root-mac');
  const elSrcMac = document.getElementById('input-src-mac');
  const elLinkSpeed = document.getElementById('select-link-speed');
  const elPortRole = document.getElementById('select-port-role');
  const elPortNum = document.getElementById('input-port-num');
  const elPortPriority = document.getElementById('input-port-priority');

  const elHelloTime = document.getElementById('input-hello-time');
  const elForwardDelay = document.getElementById('input-forward-delay');
  const elMaxAge = document.getElementById('input-max-age');
  const elNetworkDiameter = document.getElementById('input-network-diameter');
  const elMstRegion = document.getElementById('input-mst-region');
  const elMstRevision = document.getElementById('input-mst-revision');

  const elChkBpduGuard = document.getElementById('chk-bpdu-guard');
  const elChkRootGuard = document.getElementById('chk-root-guard');
  const elChkLoopGuard = document.getElementById('chk-loop-guard');
  const elChkTcDamping = document.getElementById('chk-tc-damping');
  const elChkMstDigest = document.getElementById('chk-mst-digest');
  const elChkBorderFilter = document.getElementById('chk-border-filter');
  const elChkP2pType = document.getElementById('chk-p2p-type');
  const elChkCoppBpdu = document.getElementById('chk-copp-bpdu');
  const elChkPortFast = document.getElementById('chk-portfast');

  const elValConvergenceTime = document.getElementById('val-convergence-time');
  const elValFrameSize = document.getElementById('val-frame-size');
  const elValNetworkDiameter = document.getElementById('val-network-diameter');
  const elValMacAgingTc = document.getElementById('val-mac-aging-tc');

  const elBadgeStpMode = document.getElementById('badge-stp-mode');
  const elBadgeTimerStatus = document.getElementById('badge-timer-status');
  const elScoreBanner = document.getElementById('score-banner');
  const elScoreGrade = document.getElementById('score-grade');
  const elScoreTitle = document.getElementById('score-title');
  const elScoreSummary = document.getElementById('score-summary');
  const elFindingsContainer = document.getElementById('findings-container');

  const elBadgeWireframeDesc = document.getElementById('badge-wireframe-desc');
  const elPacketHexDump = document.getElementById('packet-hex-dump');
  const elSynthOutput = document.getElementById('synth-output');
  const elBtnCopy = document.getElementById('btn-copy-config');

  function getFormConfig() {
    const speed = elLinkSpeed.value;
    const cost = STPProtocolEngine.LINK_PATH_COSTS[speed] ? STPProtocolEngine.LINK_PATH_COSTS[speed].cost : 2000;

    return {
      protocolMode: elProtocolMode.value,
      vlanId: parseInt(elVlanId.value, 10) || 1,
      rootPriority: parseInt(elRootPriority.value, 10),
      bridgePriority: parseInt(elBridgePriority.value, 10),
      rootMac: elRootMac.value.trim(),
      srcMac: elSrcMac.value.trim(),
      rootPathCost: cost,
      portRole: parseInt(elPortRole.value, 10),
      portNumber: parseInt(elPortNum.value, 10) || 1,
      portPriority: parseInt(elPortPriority.value, 10) || 128,
      helloTime: parseFloat(elHelloTime.value) || 2.0,
      forwardDelay: parseFloat(elForwardDelay.value) || 15.0,
      maxAge: parseFloat(elMaxAge.value) || 20.0,
      networkDiameter: parseInt(elNetworkDiameter.value, 10) || 7,
      mstRegionName: elMstRegion.value.trim(),
      mstRevision: parseInt(elMstRevision.value, 10) || 1,
      bpduGuardEnabled: elChkBpduGuard.checked,
      rootGuardEnabled: elChkRootGuard.checked,
      loopGuardEnabled: elChkLoopGuard.checked,
      tcDampingEnabled: elChkTcDamping.checked,
      mstDigestAligned: elChkMstDigest.checked,
      borderBpduFilter: elChkBorderFilter.checked,
      p2pLinkType: elChkP2pType.checked,
      coppBpduProtection: elChkCoppBpdu.checked,
      portFastEnabled: elChkPortFast.checked,
      flagAgreement: true,
      flagForwarding: true,
      flagLearning: true
    };
  }

  function applyPreset(presetKey) {
    const p = PRESETS[presetKey];
    if (!p) return;

    elProtocolMode.value = p.protocolMode;
    elVlanId.value = p.vlanId;
    elRootPriority.value = p.rootPriority.toString();
    elBridgePriority.value = p.bridgePriority.toString();
    elRootMac.value = p.rootMac;
    elSrcMac.value = p.srcMac;
    elPortRole.value = p.portRole.toString();
    elPortNum.value = p.portNumber;
    elPortPriority.value = p.portPriority;
    elHelloTime.value = p.helloTime;
    elForwardDelay.value = p.forwardDelay;
    elMaxAge.value = p.maxAge;
    elNetworkDiameter.value = p.networkDiameter;
    elMstRegion.value = p.mstRegionName;
    elMstRevision.value = p.mstRevision;

    elChkBpduGuard.checked = p.bpduGuardEnabled;
    elChkRootGuard.checked = p.rootGuardEnabled;
    elChkLoopGuard.checked = p.loopGuardEnabled;
    elChkTcDamping.checked = p.tcDampingEnabled;
    elChkMstDigest.checked = p.mstDigestAligned;
    elChkBorderFilter.checked = p.borderBpduFilter;
    elChkP2pType.checked = p.p2pLinkType;
    elChkCoppBpdu.checked = p.coppBpduProtection;
    elChkPortFast.checked = p.portFastEnabled;

    document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById(`btn-preset-${presetKey}`);
    if (btn) btn.classList.add('active');

    updateAll();
  }

  function updateAll() {
    const cfg = getFormConfig();

    // 1. Badge Status
    elBadgeStpMode.textContent = cfg.protocolMode === 'MSTP' ? 'IEEE 802.1s MSTP' : (cfg.protocolMode === 'RSTP' ? 'IEEE 802.1w RSTP' : 'Legacy 802.1D');

    // 2. Convergence Calculations
    const conv = STPProtocolEngine.calculateConvergence({
      protocolMode: cfg.protocolMode,
      portFastEnabled: cfg.portFastEnabled,
      forwardDelay: cfg.forwardDelay,
      maxAge: cfg.maxAge,
      networkDiameter: cfg.networkDiameter
    });

    elValConvergenceTime.textContent = cfg.portFastEnabled ? '0.0s (Edge)' : (conv.mode === 'STP_8021D' ? '50.0s' : '< 1.0s');
    elValNetworkDiameter.textContent = `${cfg.networkDiameter} Hops`;
    elValMacAgingTc.textContent = `${conv.macAgingTcSec} Sec`;

    // 3. Binary BPDU Encoding & Hex Dissector
    const encoded = STPProtocolEngine.encodeBPDU(cfg);
    elValFrameSize.textContent = `${encoded.totalLength} Bytes`;
    elBadgeWireframeDesc.textContent = `${encoded.totalLength} Bytes BPDU (Payload: ${encoded.payloadLength}B)`;

    const hexDump = STPProtocolEngine.formatHexDump(encoded.frameBytes);
    elPacketHexDump.textContent = hexDump;

    // 4. 10-Point Zero-Trust Audit
    const audit = STPSecurityAuditor.auditSTPSecurity(cfg);
    elScoreGrade.textContent = audit.grade;
    elScoreTitle.textContent = `${audit.totalScore} / ${audit.maxScore} Points (${audit.passed ? 'Passed' : 'Failed'})`;
    elScoreSummary.textContent = audit.summary;
    elScoreBanner.className = `score-badge-large ${audit.passed ? 'grade-A' : 'grade-F'}`;

    elFindingsContainer.innerHTML = '';
    audit.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = `finding-item ${f.status.toLowerCase()}`;
      item.innerHTML = `
        <div class="finding-title">
          <span>${f.name}</span>
          <span style="font-family: var(--font-mono);">${f.score}/${f.maxScore} pts</span>
        </div>
        <div class="finding-desc">${f.description}</div>
        ${f.remediation ? `<div class="finding-remediation">Remediation: ${f.remediation}</div>` : ''}
      `;
      elFindingsContainer.appendChild(item);
    });

    // 5. Configuration Synthesizer Output
    renderSynthesizer(cfg);
  }

  function renderSynthesizer(cfg) {
    let code = '';
    if (activeTab === 'cisco') {
      code = STPConfigSynthesizer.generateCisco(cfg);
    } else if (activeTab === 'arista') {
      code = STPConfigSynthesizer.generateArista(cfg);
    } else if (activeTab === 'junos') {
      code = STPConfigSynthesizer.generateJunos(cfg);
    } else if (activeTab === 'linux') {
      code = STPConfigSynthesizer.generateLinux(cfg);
    } else if (activeTab === 'prom') {
      code = STPConfigSynthesizer.generatePrometheus(cfg);
    }
    elSynthOutput.textContent = code;
  }

  // Event Listeners
  document.getElementById('btn-preset-core').addEventListener('click', () => applyPreset('core'));
  document.getElementById('btn-preset-campus').addEventListener('click', () => applyPreset('campus'));
  document.getElementById('btn-preset-vulnerable').addEventListener('click', () => applyPreset('vulnerable'));
  document.getElementById('btn-recalculate').addEventListener('click', updateAll);

  [elProtocolMode, elVlanId, elRootPriority, elBridgePriority, elRootMac, elSrcMac,
   elLinkSpeed, elPortRole, elPortNum, elPortPriority, elHelloTime, elForwardDelay,
   elMaxAge, elNetworkDiameter, elMstRegion, elMstRevision, elChkBpduGuard, elChkRootGuard,
   elChkLoopGuard, elChkTcDamping, elChkMstDigest, elChkBorderFilter, elChkP2pType,
   elChkCoppBpdu, elChkPortFast
  ].forEach(input => {
    input.addEventListener('input', updateAll);
    input.addEventListener('change', updateAll);
  });

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      e.target.classList.add('active');
      activeTab = e.target.getAttribute('data-tab');
      renderSynthesizer(getFormConfig());
    });
  });

  elBtnCopy.addEventListener('click', () => {
    navigator.clipboard.writeText(elSynthOutput.textContent).then(() => {
      elBtnCopy.textContent = 'Copied!';
      setTimeout(() => { elBtnCopy.textContent = 'Copy Config'; }, 2000);
    });
  });

  // Initialize
  applyPreset('core');
})();
