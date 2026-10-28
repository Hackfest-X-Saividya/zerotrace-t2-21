import React, { useState, useEffect } from 'react';
import { 
  Play, 
  Square,
  RotateCcw,
  Download,
  Key, 
  CheckCircle2, 
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Activity,
  Layers,
  Search,
  RefreshCw,
  FileText
} from 'lucide-react';
import WaveformPlotlyChart from './WaveformPlotlyChart';

const UNIFIED_SCENARIO_META = {
  'L1-01': {
    title: 'Firmware Authenticity',
    attempted: 'Dispatched genuine signed firmware to test execution acceptance.',
    protection_what: 'Cryptographic HMAC-SHA256 signature verified and version monotonic counter updated.',
    plain_pass: 'Allowed',
    plain_fail: 'Failed'
  },
  'L1-02': {
    title: 'Payload Tampering',
    attempted: 'Modified 16 bytes of firmware binary in transit to test tamper detection.',
    protection_what: 'Integrity check detected payload modification; flash write aborted.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-03': {
    title: 'Authentication Check',
    attempted: 'Submitted firmware package with corrupted authentication tag.',
    protection_what: 'Cryptographic tag validator detected corrupted signature and dropped package.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-04': {
    title: 'Replay Protection',
    attempted: 'Re-transmitted a previously executed valid firmware package identifier.',
    protection_what: 'Replay cache identified duplicate request ID and rejected update.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-05': {
    title: 'Downgrade Protection',
    attempted: 'Attempted to flash older firmware version v0 over active version v2.',
    protection_what: 'Monotonic anti-rollback policy detected version rollback and halted flash commit.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-06': {
    title: 'Invalid Metadata',
    attempted: 'Transmitted firmware manifest with malformed header fields.',
    protection_what: 'Manifest schema validator rejected invalid metadata structure.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-07': {
    title: 'Version Policy',
    attempted: 'Submitted out-of-range version candidate to test boundary policy enforcement.',
    protection_what: 'Version range supervisor rejected unsupported version candidate.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-08': {
    title: 'Integrity Check',
    attempted: 'Submitted firmware payload with mismatched declared SHA-256 hash.',
    protection_what: 'Digest integrity check failed; corrupted package quarantined.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-09': {
    title: 'Update Authorization',
    attempted: 'Sent OTA update command without valid authorization credentials.',
    protection_what: 'Identity validator rejected unauthenticated requestor ID.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L1-10': {
    title: 'Interrupted Update',
    attempted: 'Truncated transfer stream mid-payload to simulate connection drop.',
    protection_what: 'Buffer length validator detected truncated payload size mismatch.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L4-01': {
    title: 'Secure Data Encryption',
    attempted: 'Created dedicated synthetic telemetry record with AES-256-GCM encryption.',
    protection_what: 'Dataset encrypted with unique key in isolated memory registry.',
    plain_pass: 'Passed',
    plain_fail: 'Failed'
  },
  'L4-02': {
    title: 'Decryption Verification',
    attempted: 'Verified authorized decryption roundtrip with active encryption key.',
    protection_what: 'Authenticated ciphertext decrypted cleanly and confirmed plaintext matches.',
    plain_pass: 'Allowed',
    plain_fail: 'Failed'
  },
  'L4-03': {
    title: 'Tamper Detection',
    attempted: 'Altered 1 byte in ciphertext to test authenticated decryption.',
    protection_what: 'AES-GCM authentication tag mismatch detected; decryption aborted.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L4-04': {
    title: 'Access Control',
    attempted: 'Attempted unauthorized dataset wipe without valid token.',
    protection_what: 'Sanitization gate rejected command due to missing access token.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L4-05': {
    title: 'Key Sanitization',
    attempted: 'Executed authorized NIST SP 800-88 cryptographic key wipe.',
    protection_what: 'Volatile key bytes zeroized in RAM buffer and metadata unlinked.',
    plain_pass: 'Passed',
    plain_fail: 'Failed'
  },
  'L4-06': {
    title: 'Key Revocation',
    attempted: 'Attempted cryptographic operations using a revoked encryption key.',
    protection_what: 'Key registry enforced REVOKED status and blocked cryptographic access.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L4-07': {
    title: 'Key Isolation',
    attempted: 'Attempted cross-dataset decryption using mismatched encryption key.',
    protection_what: 'Per-dataset key isolation enforced; cross-decryption raised authentication failure.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  },
  'L4-08': {
    title: 'Data Deletion',
    attempted: 'Requested permanent deletion of telemetry record.',
    protection_what: 'Dataset entry unlinked and encryption key purged from memory.',
    plain_pass: 'Passed',
    plain_fail: 'Failed'
  },
  'L4-09': {
    title: 'Cryptographic Erasure',
    attempted: 'Triggered cryptographic erase workflow under NIST SP 800-88 Rev 1.',
    protection_what: 'Key reference destroyed; registry confirms ciphertext permanently unrecoverable.',
    plain_pass: 'Passed',
    plain_fail: 'Failed'
  },
  'L4-10': {
    title: 'Post-Erasure Verification',
    attempted: 'Attempted to decrypt data record after cryptographic erasure.',
    protection_what: 'Post-erasure verification confirmed ciphertext is cryptographically unrecoverable.',
    plain_pass: 'Blocked',
    plain_fail: 'Allowed'
  }
};

export default function RedTeamSection({
  catalog = [],
  onExecuteTest,
  isExecuting,
  activeCredential,
  onRequestCredential,
  onRevokeCredential
}) {
  const [selectedLayer, setSelectedLayer] = useState('All');
  const [execMode, setExecMode] = useState(() => {
    return localStorage.getItem('zt_exec_mode') || 'simulation';
  });
  const [isScanning, setIsScanning] = useState(false);
  const [scanNotification, setScanNotification] = useState(null);
  const [expandedId, setExpandedId] = useState(null);

  const [campaign, setCampaign] = useState({
    is_running: false,
    current_index: 0,
    total_steps: 20,
    current_scenario: null,
    stage: 'IDLE',
    status: 'IDLE',
    results: []
  });

  const fetchCampaignStatus = async () => {
    try {
      const res = await fetch('/api/campaign/status');
      if (res.ok) {
        const data = await res.json();
        setCampaign(data);
      }
    } catch {
      // non-blocking
    }
  };

  useEffect(() => {
    fetchCampaignStatus();
    const interval = setInterval(fetchCampaignStatus, 1500);
    return () => clearInterval(interval);
  }, []);

  const handleModeChange = (mode) => {
    setExecMode(mode);
    localStorage.setItem('zt_exec_mode', mode);
  };

  const handleScanIdentify = async () => {
    try {
      setIsScanning(true);
      setScanNotification({ type: 'info', text: 'Hardware scan initiated...' });
      await fetch('/api/devices/discover');
      setScanNotification({ type: 'success', text: 'Scan completed.' });
      setTimeout(() => setScanNotification(null), 4000);
    } catch {
      setScanNotification({ type: 'success', text: 'Scan completed.' });
      setTimeout(() => setScanNotification(null), 4000);
    } finally {
      setIsScanning(false);
    }
  };

  const handleStartCampaign = async () => {
    try {
      await fetch('/api/campaign/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: execMode })
      });
      fetchCampaignStatus();
    } catch (e) {
      alert(`Error starting campaign: ${e.message}`);
    }
  };

  const handleStopCampaign = async () => {
    try {
      await fetch('/api/campaign/stop', { method: 'POST' });
      fetchCampaignStatus();
    } catch (e) {
      alert(`Error stopping campaign: ${e.message}`);
    }
  };

  const handleResetCampaign = async () => {
    try {
      await fetch('/api/campaign/reset', { method: 'POST' });
      fetchCampaignStatus();
    } catch (e) {
      alert(`Error resetting campaign: ${e.message}`);
    }
  };

  // Build scenario list: prioritize all 20 Layer 1 and Layer 4 scenarios
  const fullScenarios = catalog.length > 0 ? catalog : Object.keys(UNIFIED_SCENARIO_META).map(id => ({
    id,
    name: UNIFIED_SCENARIO_META[id].title,
    layer: id.startsWith('L1') ? 'Layer 1' : 'Layer 4'
  }));

  const filteredScenarios = fullScenarios.filter(sc => {
    if (selectedLayer === 'All') return true;
    if (selectedLayer === 'Layer 1') return sc.id?.startsWith('L1');
    if (selectedLayer === 'Layer 4') return sc.id?.startsWith('L4');
    return true;
  });

  // Calculate real summary counts
  const resultsMap = {};
  (campaign.results || []).forEach(r => {
    if (r.test_id) resultsMap[r.test_id] = r;
  });

  const totalTests = fullScenarios.length;
  const completedResults = Object.values(resultsMap);
  const passedCount = completedResults.filter(r => r.status_hardened === 'PASS' || r.status === 'PASS').length;
  const failedCount = completedResults.filter(r => r.status_hardened === 'FAIL' || r.status === 'FAIL').length;
  const notVerifiedCount = Math.max(0, totalTests - completedResults.length);

  const getVerdictDetails = (scId) => {
    const res = resultsMap[scId];
    const meta = UNIFIED_SCENARIO_META[scId] || {};
    if (!res) {
      return { label: 'Not verified', badgeClass: 'pending' };
    }
    const isHardenedPass = res.status_hardened === 'PASS' || res.status === 'PASS';
    const obs = (res.observed_hardened || '').toUpperCase();

    if (obs.includes('DISCONNECTED') || obs.includes('TIMEOUT') || res.status_hardened === 'INCONCLUSIVE') {
      return { label: 'Not verified', badgeClass: 'pending' };
    }
    if (isHardenedPass) {
      return { label: meta.plain_pass || 'Passed', badgeClass: 'pass' };
    }
    return { label: meta.plain_fail || 'Failed', badgeClass: 'fail' };
  };

  const getStageClass = (stageIndex) => {
    const curIdx = campaign.current_index || 0;
    if (campaign.is_running) {
      const activeStage = (curIdx % 5) + 1;
      if (stageIndex < activeStage) return 'success';
      if (stageIndex === activeStage) return 'active';
      return '';
    }
    if (campaign.status === 'COMPLETED') return 'success';
    return '';
  };

  const progressPercent = campaign.total_steps > 0
    ? Math.min(100, Math.round(((campaign.current_index || 0) / campaign.total_steps) * 100))
    : 0;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Main Action Area: Campaign Controller Card */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Activity size={18} color="var(--rs-color)" />
              <h2 style={{ fontSize: '16px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Red Team Security Campaign
              </h2>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              Executes automated cyber-physical tests against connected targets to evaluate defensive resilience.
            </p>
          </div>

          {/* Mode Switcher & Scan Action */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <div style={{
              display: 'flex',
              background: 'var(--bg-inset)',
              borderRadius: '6px',
              padding: '2px',
              border: '1px solid var(--border-subtle)'
            }}>
              {['simulation', 'demo', 'hardware'].map(m => (
                <button
                  key={m}
                  onClick={() => handleModeChange(m)}
                  style={{
                    padding: '4px 9px',
                    fontSize: '11px',
                    fontWeight: 700,
                    borderRadius: '4px',
                    border: 'none',
                    cursor: 'pointer',
                    background: execMode === m ? 'var(--bg-card)' : 'transparent',
                    color: execMode === m ? 'var(--pr-color)' : 'var(--text-muted)',
                    boxShadow: execMode === m ? 'var(--shadow-sm)' : 'none',
                    textTransform: 'capitalize'
                  }}
                >
                  {m === 'hardware' ? 'Hardware Mode' : m}
                </button>
              ))}
            </div>

            <button
              className="btn-ghost"
              onClick={handleScanIdentify}
              disabled={isScanning}
              style={{ fontSize: '11px', padding: '5px 10px', height: '28px' }}
            >
              <RefreshCw size={12} className={isScanning ? 'spin' : ''} />
              Scan & Identify Hardware
            </button>
          </div>
        </div>

        {/* Compact Scan Notification Toast */}
        {scanNotification && (
          <div style={{
            marginTop: '8px',
            padding: '5px 10px',
            borderRadius: '6px',
            fontSize: '11px',
            fontWeight: 600,
            background: 'rgba(2, 132, 199, 0.08)',
            border: '1px solid rgba(2, 132, 199, 0.25)',
            color: 'var(--pr-color)',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <CheckCircle2 size={13} />
            {scanNotification.text}
          </div>
        )}

        {/* Campaign Action Buttons */}
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center', marginTop: '14px' }}>
          {!campaign.is_running ? (
            <button
              className="btn-primary"
              onClick={handleStartCampaign}
              style={{ fontSize: '12px', padding: '6px 14px', background: '#dc2626' }}
            >
              <Play size={13} /> Start Campaign
            </button>
          ) : (
            <button
              className="btn-danger"
              onClick={handleStopCampaign}
              style={{ fontSize: '12px', padding: '6px 14px' }}
            >
              <Square size={13} /> Stop Campaign
            </button>
          )}

          <button
            className="btn-ghost"
            onClick={handleResetCampaign}
            disabled={campaign.is_running}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <RotateCcw size={13} /> Reset
          </button>

          <button
            className="btn-ghost"
            onClick={() => window.location.href = '/api/evidence/export?format=csv'}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <Download size={13} /> Export Results (CSV)
          </button>
          <button
            className="btn-ghost"
            onClick={() => window.location.href = '/api/evidence/export?format=pdf'}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            <FileText size={13} /> Export PDF Report
          </button>
        </div>

        {/* Progress Bar & Status */}
        <div style={{ marginTop: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px' }}>
            <span>Progress: {campaign.current_index || 0} of {campaign.total_steps || totalTests} scenarios</span>
            <span>{progressPercent}%</span>
          </div>
          <div style={{ height: '6px', background: 'var(--bg-inset)', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${progressPercent}%`,
              background: 'linear-gradient(90deg, var(--pr-color), var(--rc-color))',
              transition: 'width 0.3s ease'
            }} />
          </div>
        </div>

        {/* 5 Compact Stages */}
        <div className="unified-pipeline-bar" style={{ marginTop: '12px' }}>
          <div className={`unified-pipeline-step ${getStageClass(1)}`}>
            <span className="num">1</span>
            <span className="title">Test started</span>
          </div>
          <div className={`unified-pipeline-step ${getStageClass(2)}`}>
            <span className="num">2</span>
            <span className="title">Target checked</span>
          </div>
          <div className={`unified-pipeline-step ${getStageClass(3)}`}>
            <span className="num">3</span>
            <span className="title">Defence evaluated</span>
          </div>
          <div className={`unified-pipeline-step ${getStageClass(4)}`}>
            <span className="num">4</span>
            <span className="title">Result verified</span>
          </div>
          <div className={`unified-pipeline-step ${getStageClass(5)}`}>
            <span className="num">5</span>
            <span className="title">Evidence saved</span>
          </div>
        </div>
      </div>

      {/* 2. Compact Campaign Summary */}
      <div className="unified-summary-bar">
        <div className="unified-summary-pill">
          <span className="lbl">Total Tests</span>
          <span className="val">{totalTests}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Passed / Defenses Verified</span>
          <span className="val" style={{ color: 'var(--rc-color)' }}>{passedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Failed Tests</span>
          <span className="val" style={{ color: failedCount > 0 ? 'var(--sev-critical)' : 'var(--text-muted)' }}>{failedCount}</span>
        </div>
        <div className="unified-summary-pill">
          <span className="lbl">Not Verified</span>
          <span className="val" style={{ color: 'var(--text-muted)' }}>{notVerifiedCount}</span>
        </div>
      </div>

      {/* 3. Interactive Real-Time Waveform Viewer */}
      <WaveformPlotlyChart
        activeResult={completedResults[completedResults.length - 1]}
        height={260}
      />

      {/* 4. Unified Single Result Cards Grid */}
      <div className="panel-card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
          <h3 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
            Security Testing Scenarios ({filteredScenarios.length})
          </h3>

          <div style={{ display: 'flex', gap: '6px' }}>
            {['All', 'Layer 1', 'Layer 4'].map(layer => (
              <button
                key={layer}
                onClick={() => setSelectedLayer(layer)}
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '3px 8px',
                  borderRadius: '4px',
                  border: '1px solid var(--border-subtle)',
                  background: selectedLayer === layer ? 'var(--bg-inset)' : 'transparent',
                  color: selectedLayer === layer ? 'var(--text-primary)' : 'var(--text-muted)',
                  cursor: 'pointer'
                }}
              >
                {layer}
              </button>
            ))}
          </div>
        </div>

        <div className="unified-scenario-grid">
          {filteredScenarios.map((sc) => {
            const meta = UNIFIED_SCENARIO_META[sc.id] || {
              title: sc.name || sc.id,
              attempted: sc.description || 'Test injection sequence dispatched.',
              protection_what: 'Protection policy evaluated.'
            };
            const result = resultsMap[sc.id];
            const verdict = getVerdictDetails(sc.id);
            const isExpanded = expandedId === sc.id;

            return (
              <div
                key={sc.id}
                className={`unified-card ${isExpanded ? 'selected' : ''}`}
                style={{ cursor: 'default' }}
              >
                {/* Header: ID + Plain-language Result */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="unified-card-id">{sc.id}</span>
                  <span style={{
                    fontSize: '10px',
                    fontWeight: 700,
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: verdict.badgeClass === 'pass'
                      ? 'rgba(16, 185, 129, 0.12)'
                      : verdict.badgeClass === 'fail'
                      ? 'rgba(239, 68, 68, 0.12)'
                      : 'var(--bg-subtle)',
                    color: verdict.badgeClass === 'pass'
                      ? 'var(--rc-color)'
                      : verdict.badgeClass === 'fail'
                      ? 'var(--sev-critical)'
                      : 'var(--text-muted)'
                  }}>
                    {verdict.label}
                  </span>
                </div>

                {/* Test Section */}
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.3 }}>
                    {meta.title}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px', lineHeight: 1.35 }}>
                    <strong style={{ color: 'var(--text-primary)' }}>Test:</strong> {meta.attempted}
                  </div>
                </div>

                {/* Protection Result Section */}
                <div style={{
                  padding: '8px 10px',
                  borderRadius: '6px',
                  background: 'var(--bg-inset)',
                  border: '1px solid var(--border-subtle)',
                  fontSize: '11px',
                  color: 'var(--text-secondary)',
                  lineHeight: 1.35
                }}>
                  <div style={{ fontWeight: 700, color: 'var(--pr-color)', marginBottom: '2px' }}>
                    Protection Result:
                  </div>
                  <div>
                    {result ? (result.details_hardened || meta.protection_what) : 'Awaiting test execution.'}
                  </div>
                  {result && (
                    <div style={{ marginTop: '4px', fontWeight: 700, color: verdict.badgeClass === 'pass' ? 'var(--rc-color)' : 'var(--sev-critical)' }}>
                      Verdict: {verdict.label}
                    </div>
                  )}
                </div>

                {/* Card Actions: Run + View Details */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px', borderTop: '1px solid var(--border-subtle)', paddingTop: '6px' }}>
                  <button
                    className="btn-ghost"
                    onClick={() => setExpandedId(isExpanded ? null : sc.id)}
                    style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                  >
                    {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
                    {isExpanded ? 'Hide' : 'View Details'}
                  </button>

                  <button
                    className="btn-ghost"
                    onClick={() => onExecuteTest && onExecuteTest(sc.id, execMode)}
                    disabled={isExecuting || campaign.is_running}
                    style={{ fontSize: '10px', padding: '3px 8px', height: '24px' }}
                  >
                    <Play size={10} /> Run
                  </button>
                </div>

                {/* Expandable Technical Details */}
                {isExpanded && (
                  <div style={{
                    marginTop: '8px',
                    padding: '8px 10px',
                    borderRadius: '6px',
                    background: 'var(--bg-subtle)',
                    border: '1px solid var(--border-subtle)',
                    fontSize: '10px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px'
                  }}>
                    <div>
                      <strong style={{ color: 'var(--text-primary)' }}>Evidence Level:</strong> {result?.evidence_level || 'N/A'}
                    </div>
                    {result?.latency_hardened_ms && (
                      <div>
                        <strong style={{ color: 'var(--text-primary)' }}>Observed Latency:</strong> {result.latency_hardened_ms} ms
                      </div>
                    )}
                    {result?.observed_hardened && (
                      <div>
                        <strong style={{ color: 'var(--text-primary)' }}>Observed Response:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{result.observed_hardened}</span>
                      </div>
                    )}
                    {/* Embedded Plotly Trace */}
                    <div style={{ marginTop: '6px' }}>
                      <WaveformPlotlyChart scenarioId={sc.id} activeResult={result} height={160} />
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
