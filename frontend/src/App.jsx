import React, { useState, useEffect } from 'react';

// Navigation & Modals
import Navigation from './components/Navigation';
import { LimitationsModal, WiringModal, CredentialModal, ConfirmSanitizeModal } from './components/Modals';

// Feature Sections
import OverviewSection from './components/OverviewSection';
import RedTeamSection from './components/RedTeamSection';
import BlueTeamSection from './components/BlueTeamSection';
import Layer1Section from './components/Layer1Section';
import Layer2Section from './components/Layer2Section';
import Layer3Section from './components/Layer3Section';
import Layer4Section from './components/Layer4Section';
import LiveEventsSection from './components/LiveEventsSection';
import AuditHistorySection from './components/AuditHistorySection';
import DeviceStatusSection from './components/DeviceStatusSection';
import TestReportsSection from './components/TestReportsSection';
import SettingsSection from './components/SettingsSection';

export default function App() {
  // Navigation State
  const [activeSection, setActiveSection] = useState('blue');
  const [showLimitationsModal, setShowLimitationsModal] = useState(false);
  const [showWiringModal, setShowWiringModal] = useState(false);
  const [showCredentialModal, setShowCredentialModal] = useState(false);
  const [modalCredential, setModalCredential] = useState(null);
  const [showSanitizeModal, setShowSanitizeModal] = useState(false);
  const [sanitizeTargetDatasetId, setSanitizeTargetDatasetId] = useState(null);

  // Hardware Devices State
  const [devices, setDevices] = useState({
    baseline: {
      name: "Target A — ESP8266 NodeMCU (Baseline)",
      port: null,
      arch: "esp8266",
      connected: false,
      verified: false,
      chip: null,
      error_msg: null
    },
    hardened: {
      name: "Target B — ESP32 DevKit (Hardened)",
      port: null,
      arch: "esp32",
      connected: false,
      verified: false,
      chip: null,
      error_msg: null
    },
    uno: {
      name: "Arduino Uno Target (Optional Hardware-Assisted Monitor)",
      port: null,
      arch: "avr",
      connected: false,
      verified: false,
      optional: true
    }
  });

  const [availablePorts, setAvailablePorts] = useState([]);
  const [catalog, setCatalog] = useState([]);
  const [results, setResults] = useState([]);
  const [events, setEvents] = useState([]);
  const [auditTrail, setAuditTrail] = useState([]);
  const [findings, setFindings] = useState([]);
  const [rawLogs, setRawLogs] = useState([]);
  const [csfCoverage, setCsfCoverage] = useState(null);
  const [overviewData, setOverviewData] = useState(null);
  const [activeCredential, setActiveCredential] = useState(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const [isLanMode, setIsLanMode] = useState(false);

  // Synchronize active section with URL query parameters (?view=red or ?view=blue)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const view = params.get('view');
    const sec = params.get('section');
    if (view === 'red' || view === 'blue') {
      setActiveSection(view);
    } else if (sec) {
      setActiveSection(sec);
    }
  }, []);

  const handleSelectSection = (sectionId) => {
    setActiveSection(sectionId);
    const url = new URL(window.location);
    if (sectionId === 'red' || sectionId === 'blue') {
      url.searchParams.set('view', sectionId);
      url.searchParams.delete('section');
    } else {
      url.searchParams.set('section', sectionId);
      url.searchParams.delete('view');
    }
    window.history.pushState({}, '', url);
  };

  // Fetch initial state from backend
  const fetchInitialData = async () => {
    try {
      const [catRes, portRes, covRes, healthRes, evRes, auditRes, findRes, credRes] = await Promise.allSettled([
        fetch('/api/catalog'),
        fetch('/api/ports'),
        fetch('/api/csf-coverage'),
        fetch('/api/health'),
        fetch('/api/events?limit=50'),
        fetch('/api/audit/trail?limit=50'),
        fetch('/api/blue-team/findings?limit=50'),
        fetch('/api/access/list')
      ]);

      if (catRes.status === 'fulfilled' && catRes.value.ok) {
        const catData = await catRes.value.json();
        setCatalog(catData.scenarios || []);
      }

      if (portRes.status === 'fulfilled' && portRes.value.ok) {
        const portData = await portRes.value.json();
        setAvailablePorts(portData.ports || []);
      }

      if (covRes.status === 'fulfilled' && covRes.value.ok) {
        const covData = await covRes.value.json();
        setCsfCoverage(covData);
      }

      if (healthRes.status === 'fulfilled' && healthRes.value.ok) {
        const healthData = await healthRes.value.json();
        setIsLanMode(Boolean(healthData.lan_mode));
        if (healthData.devices) {
          setDevices(prev => ({
            ...prev,
            baseline: { ...prev.baseline, ...healthData.devices.baseline },
            hardened: { ...prev.hardened, ...healthData.devices.hardened },
            uno: { ...prev.uno, ...healthData.devices.uno }
          }));
        }
      }

      if (evRes.status === 'fulfilled' && evRes.value.ok) {
        const evData = await evRes.value.json();
        setEvents(evData.events || []);
      }

      if (auditRes.status === 'fulfilled' && auditRes.value.ok) {
        const aData = await auditRes.value.json();
        setAuditTrail(aData.audit_trail || []);
      }

      if (findRes.status === 'fulfilled' && findRes.value.ok) {
        const fData = await findRes.value.json();
        setFindings(fData.findings || []);
      }

      if (credRes.status === 'fulfilled' && credRes.value.ok) {
        const credData = await credRes.value.json();
        if (credData.credentials && credData.credentials.length > 0) {
          setActiveCredential(credData.credentials[0]);
        }
      }

      // Fetch overview data
      const ovRes = await fetch('/api/overview');
      if (ovRes.ok) {
        const ovData = await ovRes.json();
        setOverviewData(ovData);
      }
    } catch (e) {
      console.warn("Initial data load error:", e);
    }
  };

  // Connect to SSE stream
  useEffect(() => {
    fetchInitialData();

    const evtSource = new EventSource('/api/stream');

    evtSource.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'init') {
          if (msg.payload.devices) {
            setDevices(prev => ({
              ...prev,
              baseline: { ...prev.baseline, ...msg.payload.devices.baseline },
              hardened: { ...prev.hardened, ...msg.payload.devices.hardened },
              uno: { ...prev.uno, ...msg.payload.devices.uno }
            }));
          }
          if (msg.payload.recent_tests) setResults(msg.payload.recent_tests);
          if (msg.payload.recent_events) setEvents(msg.payload.recent_events);
          if (msg.payload.active_credentials && msg.payload.active_credentials.length > 0) {
            setActiveCredential(msg.payload.active_credentials[0]);
          }
        } else if (msg.type === 'device_status') {
          setDevices(prev => {
            const next = { ...prev };
            for (const [k, v] of Object.entries(msg.payload)) {
              if (next[k]) next[k] = { ...next[k], ...v };
            }
            return next;
          });
        } else if (msg.type === 'test_result') {
          setResults(prev => [msg.payload, ...prev].slice(0, 150));
          // Refresh CSF coverage and overview
          fetch('/api/csf-coverage').then(r => r.json()).then(data => setCsfCoverage(data)).catch(() => {});
          fetch('/api/overview').then(r => r.json()).then(data => setOverviewData(data)).catch(() => {});
        } else if (msg.type === 'raw_log') {
          setRawLogs(prev => [...prev, msg.payload].slice(-300));
        } else if (msg.type === 'security_event') {
          setEvents(prev => [msg.payload, ...prev].slice(0, 150));
        } else if (msg.type === 'blue_finding') {
          setFindings(prev => [msg.payload, ...prev].slice(0, 100));
        } else if (msg.type === 'clear') {
          setResults([]);
          setRawLogs([]);
          setEvents([]);
        }
      } catch (err) {
        console.error("SSE parsing error:", err);
      }
    };

    evtSource.onerror = () => {
      console.warn("SSE connection error. Starlette will reconnect automatically.");
    };

    return () => {
      evtSource.close();
    };
  }, []);

  // Device Management Handlers
  const handleToggleConnect = async (targetKey) => {
    const dev = devices[targetKey];
    if (dev.connected) {
      try {
        await fetch(`/api/disconnect?target=${targetKey}`, { method: 'POST' });
        setDevices(prev => ({
          ...prev,
          [targetKey]: { ...prev[targetKey], connected: false, verified: false }
        }));
      } catch (e) {
        alert(`Disconnect error: ${e.message}`);
      }
    } else {
      try {
        const res = await fetch('/api/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: targetKey, port: dev.port, baud_rate: 115200 })
        });
        if (res.ok) {
          setDevices(prev => ({
            ...prev,
            [targetKey]: { ...prev[targetKey], connected: true }
          }));
        } else {
          const err = await res.json();
          alert(`Connection failed: ${err.detail || 'Port open error'}`);
        }
      } catch (e) {
        alert(`Serial error: ${e.message}`);
      }
    }
  };

  const handlePortChange = (targetKey, newPort) => {
    setDevices(prev => ({
      ...prev,
      [targetKey]: { ...prev[targetKey], port: newPort }
    }));
  };

  const handleRefreshPorts = async () => {
    try {
      const res = await fetch('/api/ports');
      if (res.ok) {
        const data = await res.json();
        setAvailablePorts(data.ports || []);
      }
    } catch (e) {
      console.warn("Port refresh error:", e);
    }
  };

  // Execution Handlers
  const handleExecuteTest = async (testId, mode = 'real') => {
    try {
      setIsExecuting(true);
      const res = await fetch('/api/execute-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test_id: testId, mode: mode })
      });
      if (res.ok) {
        const data = await res.json();
        setResults(prev => [data, ...prev]);
      } else {
        const err = await res.json();
        alert(`Execution blocked: ${err.detail}`);
      }
    } catch (e) {
      alert(`Test execution error: ${e.message}`);
    } finally {
      setIsExecuting(false);
    }
  };

  const handleRunAllTests = async () => {
    try {
      setIsExecuting(true);
      for (const sc of catalog) {
        await handleExecuteTest(sc.id, 'auto');
        await new Promise(r => setTimeout(r, 600));
      }
    } finally {
      setIsExecuting(false);
    }
  };

  const handleReset = async () => {
    try {
      await fetch('/api/reset', { method: 'POST' });
      setResults([]);
      setRawLogs([]);
      setEvents([]);
      fetchInitialData();
    } catch (e) {
      alert(`Reset error: ${e.message}`);
    }
  };

  const handleExportCsv = () => {
    window.location.href = '/api/evidence/export?format=csv';
  };

  const handleRequestCredential = (cred) => {
    setModalCredential(cred);
    setActiveCredential(cred);
    setShowCredentialModal(true);
  };

  const handleRevokeCredential = async (credId) => {
    try {
      const res = await fetch('/api/access/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential_id: credId, reason: "Manual user revocation" })
      });
      if (res.ok) {
        setActiveCredential(null);
        alert("Credential revoked.");
      }
    } catch (e) {
      alert(`Revoke error: ${e.message}`);
    }
  };

  const handleExecuteLayer1 = async (scenario) => {
    setIsExecuting(true);
    try {
      const res = await fetch('/api/layer1/ota', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: scenario,
          target_device: 'hardened',
          credential_id: activeCredential?.credential_id,
          credential_token: activeCredential?.authorization_token
        })
      });
      return await res.json();
    } catch (e) {
      console.error("Layer 1 error:", e);
      return { error: e.message };
    } finally {
      setIsExecuting(false);
    }
  };

  const handleExecuteLayer2 = async (scenario) => {
    setIsExecuting(true);
    try {
      const res = await fetch('/api/layer2/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: scenario,
          target_device: 'hardened',
          execution_mode: 'demo',
          credential_id: activeCredential?.credential_id,
          credential_token: activeCredential?.authorization_token
        })
      });
      return await res.json();
    } catch (e) {
      console.error("Layer 2 error:", e);
      return { error: e.message };
    } finally {
      setIsExecuting(false);
    }
  };

  const handleExecuteLayer3 = async (scenario) => {
    setIsExecuting(true);
    try {
      const res = await fetch('/api/layer3/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario: scenario,
          target_device: 'hardened',
          credential_id: activeCredential?.credential_id,
          credential_token: activeCredential?.authorization_token
        })
      });
      return await res.json();
    } catch (e) {
      console.error("Layer 3 error:", e);
      return { error: e.message };
    } finally {
      setIsExecuting(false);
    }
  };

  const handleOpenConfirmSanitize = (datasetId) => {
    setSanitizeTargetDatasetId(datasetId);
    setShowSanitizeModal(true);
  };

  const handleConfirmSanitize = async (datasetId) => {
    setShowSanitizeModal(false);
    setIsExecuting(true);
    try {
      const res = await fetch('/api/layer4/sanitize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dataset_id: datasetId,
          confirm: true,
          credential_id: activeCredential?.credential_id,
          authorization_token: activeCredential?.authorization_token
        })
      });
      const data = await res.json();
      alert(res.ok ? "Cryptographic Sanitization Executed: DEK destroyed." : `Sanitization failed: ${data.detail}`);
    } catch (e) {
      alert(`Sanitization error: ${e.message}`);
    } finally {
      setIsExecuting(false);
    }
  };

  const connectedCount = Object.values(devices).filter(d => d.connected).length;

  return (
    <div className="app-container">
      {/* 1. Universal Top Navigation Bar */}
      <Navigation
        activeSection={activeSection}
        onSelectSection={handleSelectSection}
        onOpenLimitations={() => setShowLimitationsModal(true)}
        onOpenWiring={() => setShowWiringModal(true)}
        devices={devices}
        connectedCount={connectedCount}
        isLanMode={isLanMode}
      />

      {/* 2. Main Content Routing */}
      <main style={{ minHeight: 'calc(100vh - 180px)' }}>
        {activeSection === 'overview' && (
          <OverviewSection
            overviewData={overviewData}
            devices={devices}
            metrics={{
              total_tests: results.length,
              hardened_mitigations_enforced: results.filter(r => r.status_hardened === 'PASS').length,
              baseline_weaknesses_observed: results.filter(r => r.status_baseline === 'FAIL').length
            }}
            csfCoverage={csfCoverage}
            onRunAllTests={handleRunAllTests}
            onReset={handleReset}
            onNavigate={handleSelectSection}
          />
        )}

        {activeSection === 'red' && (
          <RedTeamSection
            catalog={catalog}
            onExecuteTest={handleExecuteTest}
            isExecuting={isExecuting}
            activeCredential={activeCredential}
            onRequestCredential={handleRequestCredential}
            onRevokeCredential={handleRevokeCredential}
          />
        )}

        {activeSection === 'blue' && (
          <BlueTeamSection
            results={results}
            findings={findings}
            onExportCsv={handleExportCsv}
          />
        )}

        {activeSection === 'layer1' && (
          <Layer1Section
            onExecuteLayer1={handleExecuteLayer1}
            isExecuting={isExecuting}
            activeCredential={activeCredential}
            onRequestCredential={handleRequestCredential}
            isLanMode={isLanMode}
          />
        )}

        {activeSection === 'layer2' && (
          <Layer2Section
            onExecuteLayer2={handleExecuteLayer2}
            isExecuting={isExecuting}
            activeCredential={activeCredential}
            onRequestCredential={handleRequestCredential}
          />
        )}

        {activeSection === 'layer3' && (
          <Layer3Section
            onExecuteLayer3={handleExecuteLayer3}
            isExecuting={isExecuting}
            activeCredential={activeCredential}
            onRequestCredential={handleRequestCredential}
          />
        )}

        {activeSection === 'layer4' && (
          <Layer4Section
            onExecuteLayer4={handleConfirmSanitize}
            onOpenConfirmSanitize={handleOpenConfirmSanitize}
            isExecuting={isExecuting}
            activeCredential={activeCredential}
            onRequestCredential={handleRequestCredential}
          />
        )}

        {activeSection === 'events' && (
          <LiveEventsSection
            events={events}
            rawLogs={rawLogs}
            onClear={() => { setEvents([]); setRawLogs([]); }}
          />
        )}

        {activeSection === 'audit' && (
          <AuditHistorySection
            auditTrail={auditTrail}
          />
        )}

        {activeSection === 'devices' && (
          <DeviceStatusSection
            devices={devices}
            availablePorts={availablePorts}
            onToggleConnect={handleToggleConnect}
            onPortChange={handlePortChange}
            onRefreshPorts={handleRefreshPorts}
          />
        )}

        {activeSection === 'reports' && (
          <TestReportsSection
            results={results}
            metrics={{
              total_tests: results.length,
              hardened_mitigations_enforced: results.filter(r => r.status_hardened === 'PASS').length,
              baseline_weaknesses_observed: results.filter(r => r.status_baseline === 'FAIL').length
            }}
            csfCoverage={csfCoverage}
          />
        )}

        {activeSection === 'settings' && (
          <SettingsSection
            isLanMode={isLanMode}
          />
        )}
      </main>

      {/* 3. Global Informational & Access Modals */}
      <LimitationsModal
        isOpen={showLimitationsModal}
        onClose={() => setShowLimitationsModal(false)}
      />

      <WiringModal
        isOpen={showWiringModal}
        onClose={() => setShowWiringModal(false)}
      />

      <CredentialModal
        isOpen={showCredentialModal}
        onClose={() => setShowCredentialModal(false)}
        credential={modalCredential}
      />

      <ConfirmSanitizeModal
        isOpen={showSanitizeModal}
        onClose={() => setShowSanitizeModal(false)}
        onConfirm={handleConfirmSanitize}
        datasetId={sanitizeTargetDatasetId}
      />
    </div>
  );
}