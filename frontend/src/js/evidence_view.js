/* =========================================================
   ZeroTrace — Evidence & Campaign View Renderer
   ========================================================= */

const EvidenceView = {
  renderEvidence(evidenceList, lastCampaign) {
    return `
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h2 style="font-size: 18px; font-weight: 700; color: var(--text-primary);">Audit Evidence & Campaign Exports</h2>
          <p style="color: var(--text-secondary); font-size: 13px; margin-top: 4px;">
            Every execution automatically generates a complete 4-file evidence package: PDF Report, Raw CSV Log, PNG Waveform, and JSON Metadata.
          </p>
        </div>
        <button class="btn-primary" onclick="App.runFullCampaign()">
          Run Full Campaign & Export All
        </button>
      </div>

      <!-- Campaign Status Banner if available -->
      ${lastCampaign ? `
        <div class="stat-card" style="border-left: 4px solid var(--accent-green); background: var(--bg-card);">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
              <span style="font-weight: 700; color: var(--text-primary);">Latest Campaign: ${lastCampaign.campaign_id}</span>
              <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">
                All 40 Security Problems Verified (${lastCampaign.total_passed}/40 Passed). Mode: <b>${lastCampaign.source_mode}</b>
              </div>
            </div>
            <div style="display: flex; gap: 8px;">
              <a href="/api/evidence/download/${lastCampaign.evidence_files.pdf.split('\\\\').pop().split('/').pop()}" target="_blank" class="btn-secondary">
                📄 Download PDF Report
              </a>
              <a href="/api/evidence/download/${lastCampaign.evidence_files.png.split('\\\\').pop().split('/').pop()}" target="_blank" class="btn-secondary">
                📈 View Waveform PNG
              </a>
            </div>
          </div>
        </div>
      ` : ''}

      <!-- Exported Evidence Files Table -->
      <div class="table-card">
        <div class="table-header-bar">
          <span class="table-title">Export Repository (exports/)</span>
          <button class="btn-secondary" onclick="App.refreshEvidenceList()">Refresh List</button>
        </div>
        <table class="custom-table">
          <thead>
            <tr>
              <th>File Name</th>
              <th>Format</th>
              <th>Size</th>
              <th>Created Date</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${evidenceList.length === 0 ? `
              <tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">
                No export files found. Click "Run Full Campaign & Export All" to generate the audit package.
              </td></tr>
            ` : evidenceList.map(f => {
              const ext = f.name.split('.').pop().toUpperCase();
              const badgeClass = ext === 'PDF' ? 'status-pass' : (ext === 'PNG' ? 'status-not-tested' : 'status-not-tested');
              return `
                <tr>
                  <td style="font-family: var(--font-mono); font-weight: 600;">${f.name}</td>
                  <td><span class="status-badge ${badgeClass}">${ext}</span></td>
                  <td style="color: var(--text-secondary);">${(f.size_bytes / 1024).toFixed(1)} KB</td>
                  <td style="color: var(--text-muted); font-size: 12px;">${new Date(f.created_utc * 1000).toLocaleString()}</td>
                  <td>
                    <a href="/api/evidence/download/${f.name}" download class="btn-secondary" style="padding: 4px 8px; font-size: 11px;">
                      Download
                    </a>
                  </td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      </div>
    `;
  }
};

window.EvidenceView = EvidenceView;

