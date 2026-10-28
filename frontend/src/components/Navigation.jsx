import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Eye, 
  Radio, 
  Layers, 
  Activity, 
  FileText, 
  Cpu, 
  Settings, 
  AlertOctagon, 
  HelpCircle,
  Key,
  Database,
  Terminal,
  Server,
  Sun,
  Moon,
  Zap
} from 'lucide-react';

export default function Navigation({ 
  activeSection, 
  onSelectSection, 
  onOpenLimitations, 
  onOpenWiring, 
  devices,
  connectedCount, 
  isLanMode 
}) {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('zerotrace_theme') || 'light';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('zerotrace_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  const hasHardware = Boolean(
    (devices?.baseline?.connected) || (devices?.hardened?.connected)
  );

  const navItems = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'red', label: 'Red Team', icon: Radio, badge: 'Campaign' },
    { id: 'blue', label: 'Blue Team', icon: Eye, badge: 'Evidence' },
    { id: 'layer1', label: 'Layer 1: OTA', icon: Layers },
    { id: 'layer2', label: 'Layer 2: SBFT', icon: Cpu },
    { id: 'layer3', label: 'Layer 3: Silicon', icon: Shield },
    { id: 'layer4', label: 'Layer 4: Sanitization', icon: Key },
    { id: 'events', label: 'Live Events', icon: Terminal },
    { id: 'audit', label: 'Audit History', icon: FileText },
    { id: 'reports', label: 'Test Reports', icon: Database },
    { id: 'settings', label: 'Diagnostics', icon: Settings }
  ];

  return (
    <header className="top-header" style={{ flexDirection: 'column', gap: '14px', alignItems: 'stretch' }}>
      {/* Brand & Hardware Status Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', flexWrap: 'wrap', gap: '12px' }}>
        <div className="brand-section">
          <div className="brand-icon">
            <Shield size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="brand-title">ZeroTrace</span>
              <span style={{
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '6px',
                background: hasHardware ? 'rgba(5,150,105,0.12)' : 'rgba(100,116,139,0.12)',
                color: hasHardware ? '#059669' : '#64748b',
                fontWeight: 700,
                border: hasHardware ? '1px solid rgba(5,150,105,0.3)' : '1px solid rgba(100,116,139,0.25)'
              }}>
                {hasHardware ? 'Mode A: Hardware Comparative' : 'Simulation Engine'}
              </span>
            </div>
            <div className="brand-subtitle">
              <span>Embedded & IoT Security Testbed</span>
              <span className="nist-pill">NIST CSF 2.0</span>
              {isLanMode && <span style={{ fontSize: '10px', background: 'rgba(225,29,72,0.12)', color: '#e11d48', padding: '2px 6px', borderRadius: '4px', fontWeight: 600 }}>LAN 0.0.0.0</span>}
            </div>
          </div>
        </div>

        {/* Top Action Controls & Theme Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Theme Switcher Button */}
          <button
            className="btn-ghost"
            onClick={toggleTheme}
            title={`Switch to ${theme === 'light' ? 'Dark' : 'Light'} Mode`}
            style={{ padding: '6px 12px', fontSize: '12px' }}
          >
            {theme === 'light' ? <Moon size={14} /> : <Sun size={14} />}
            <span>{theme === 'light' ? 'Dark' : 'Light'}</span>
          </button>

          {/* View Links */}
          <button 
            className={`btn-ghost ${activeSection === 'blue' ? 'active' : ''}`}
            onClick={() => onSelectSection('blue')}
            style={{ padding: '6px 12px', fontSize: '12px' }}
          >
            <Eye size={14} /> Blue Team
          </button>
          <button 
            className={`btn-ghost ${activeSection === 'red' ? 'active' : ''}`}
            onClick={() => onSelectSection('red')}
            style={{ padding: '6px 12px', fontSize: '12px' }}
          >
            <Radio size={14} /> Red Team
          </button>
          <button className="btn-ghost" onClick={onOpenLimitations} style={{ padding: '6px 10px', fontSize: '12px' }}>
            <AlertOctagon size={14} /> Limitations
          </button>
          <button className="btn-ghost" onClick={onOpenWiring} style={{ padding: '6px 10px', fontSize: '12px' }}>
            <HelpCircle size={14} /> Setup
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: '4px',
        padding: '4px',
        background: 'var(--bg-subtle)',
        borderRadius: '10px',
        border: '1px solid var(--border-subtle)'
      }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeSection === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectSection(item.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: isActive ? 700 : 500,
                background: isActive ? 'var(--bg-card)' : 'transparent',
                color: isActive ? 'var(--pr-color)' : 'var(--text-secondary)',
                border: isActive ? '1px solid var(--border-subtle)' : '1px solid transparent',
                boxShadow: isActive ? 'var(--shadow-sm)' : 'none',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <Icon size={14} />
              <span>{item.label}</span>
              {item.badge && (
                <span style={{
                  fontSize: '9px',
                  padding: '1px 5px',
                  borderRadius: '4px',
                  background: item.id === 'red' ? 'rgba(225,29,72,0.1)' : 'rgba(2,132,199,0.1)',
                  color: item.id === 'red' ? '#e11d48' : '#0284c7',
                  fontWeight: 600
                }}>
                  {item.badge}
                </span>
              )}
              {item.count !== undefined && item.count > 0 && (
                <span style={{
                  fontSize: '9px',
                  padding: '1px 5px',
                  borderRadius: '10px',
                  background: '#059669',
                  color: '#fff',
                  fontWeight: 700
                }}>
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
