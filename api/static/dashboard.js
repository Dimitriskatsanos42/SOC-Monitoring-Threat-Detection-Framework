const state = {
  selectedSection: 'dashboard',
  alerts: [],
  events: [],
  detectionRules: [],
  threatSummary: {},
  stats: {},
  systemStatus: {},
  settings: {
    notifications: true,
    autoTriage: true,
    collectorMode: 'observe'
  }
};

const endpoints = {
  stats: '/api/stats',
  alerts: '/api/alerts',
  recentEvents: '/api/events/recent',
  systemStatus: '/api/system/status',
  detectionRules: '/api/detection-rules',
  threatSummary: '/api/threats/summary',
  demoSeed: '/api/demo/seed'
};

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: '◉' },
  { id: 'security-events', label: 'Security Events', icon: '📡' },
  { id: 'alerts', label: 'Alerts', icon: '⚑' },
  { id: 'incidents', label: 'Incidents', icon: '🚨' },
  { id: 'threat-detection', label: 'Threat Detection', icon: '🛡️' },
  { id: 'detection-rules', label: 'Detection Rules', icon: '⚙️' },
  { id: 'assets', label: 'Assets', icon: '🧱' },
  { id: 'endpoints', label: 'Endpoints', icon: '💻' },
  { id: 'users', label: 'Users', icon: '👥' },
  { id: 'logs', label: 'Logs', icon: '📝' },
  { id: 'reports', label: 'Reports', icon: '📈' },
  { id: 'search', label: 'Search', icon: '🔎' },
  { id: 'settings', label: 'Settings', icon: '⚙' }
];

const computeRiskScore = (stats) => {
  const critical = stats.alerts_by_severity?.[4] || 0;
  const high = stats.alerts_by_severity?.[3] || 0;
  const medium = stats.alerts_by_severity?.[2] || 0;
  const low = stats.alerts_by_severity?.[1] || 0;
  const score = Math.min(100, critical * 24 + high * 12 + medium * 5 + low * 2);
  return { score, critical, high, medium, low };
};

const renderRiskScore = (stats) => {
  const { score, critical, high } = computeRiskScore(stats);
  const scoreEl = document.getElementById('risk-score');
  const captionEl = document.getElementById('risk-caption');
  if (!scoreEl || !captionEl) return;

  scoreEl.textContent = score;
  scoreEl.style.color = score >= 70 ? 'var(--danger)' : score >= 35 ? 'var(--warning)' : 'var(--success)';
  captionEl.textContent = score >= 70
    ? `${critical} critical · immediate response`
    : score >= 35
      ? `${high} high priority alerts active`
      : 'Environment posture is stable';
};

const renderActivityTrack = (events, alerts) => {
  const track = document.getElementById('activity-track');
  if (!track) return;

  const items = [
    ...alerts.slice(0, 4).map((alert) => `ALERT · ${alert.threat_type} · ${alert.hostname} · ${alert.severity_name || 'Info'}`),
    ...events.slice(0, 4).map((event) => `EVENT · ${event.event_type} · ${event.hostname} · ${event.source_ip || 'local'}`)
  ];

  if (!items.length) {
    track.textContent = 'No telemetry yet — load demo data to preview the enterprise console.';
    return;
  }

  const loop = [...items, ...items].join('   •   ');
  track.textContent = loop;
};

const renderEmptyBanner = (stats) => {
  const existing = document.getElementById('empty-banner');
  if (existing) existing.remove();
  if ((stats.total_events || 0) > 0) return;

  const banner = document.createElement('section');
  banner.id = 'empty-banner';
  banner.className = 'empty-banner';
  banner.innerHTML = `
    <p>Το dashboard είναι κενό. Φορτώστε demo telemetry για επαγγελματική παρουσίαση όπως Sentinel / Splunk.</p>
    <button class="button small" type="button" id="empty-load-demo">Load demo data</button>
  `;
  document.getElementById('dashboard-view')?.prepend(banner);
  banner.querySelector('#empty-load-demo')?.addEventListener('click', loadDemoData);
};

const updateAlertBadge = (alerts) => {
  const badge = document.getElementById('alert-count-badge');
  if (!badge) return;
  const open = alerts.filter((alert) => !alert.acknowledged).length;
  badge.textContent = open;
};

const formatStatValue = (value) => {
  if (typeof value === 'number') {
    return Number.isInteger(value) ? value.toString() : value.toFixed(2);
  }
  return value ?? '0';
};

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

const renderNav = () => {
  const navContainer = document.querySelector('.nav-list');
  if (!navContainer) return;
  navContainer.innerHTML = navItems.map((item) => `
    <button type="button" class="${item.id === state.selectedSection ? 'nav-item active' : 'nav-item'}" data-section="${item.id}">
      <span>${item.icon}</span>
      <span>${item.label}</span>
    </button>
  `).join('');
};

const setDashboardVisibility = (show) => {
  const dashboardView = document.getElementById('dashboard-view');
  const sectionContent = document.getElementById('section-content');
  if (dashboardView) dashboardView.style.display = show ? 'block' : 'none';
  if (sectionContent) sectionContent.style.display = show ? 'none' : 'block';
};

const itemLabel = (sectionId) => navItems.find((item) => item.id === sectionId)?.label || 'Dashboard';

const updateSection = async (sectionId) => {
  state.selectedSection = sectionId;
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.classList.toggle('active', item.dataset.section === sectionId);
  });

  const heroTitle = document.getElementById('hero-title') || document.querySelector('.hero-copy h2');
  const heroSubtitle = document.getElementById('hero-subtitle') || document.querySelector('.hero-copy p');
  const sectionMap = {
    dashboard: {
      title: 'Real-time visibility for analysts and incident response.',
      subtitle: 'Track detections, alert posture, endpoint activity and system health from a single modern console.'
    },
    'security-events': {
      title: 'Security events and raw telemetry.',
      subtitle: 'Review recent activity by host, source IP, event type and user context.'
    },
    alerts: {
      title: 'Alert triage and response workflow.',
      subtitle: 'Review recent incidents, inspect severity levels and prioritize response actions.'
    },
    incidents: {
      title: 'Incident management and escalation.',
      subtitle: 'Coordinate active incidents with clear summaries and response posture.'
    },
    'threat-detection': {
      title: 'Threat posture and detection coverage.',
      subtitle: 'Monitor active detections, rule health and suspicious activity patterns.'
    },
    'detection-rules': {
      title: 'Detection rules and tuning.',
      subtitle: 'Inspect rule coverage and adjust detection priorities with confidence.'
    },
    assets: {
      title: 'Critical assets and exposure posture.',
      subtitle: 'Keep track of monitored assets and their current operational state.'
    },
    endpoints: {
      title: 'Endpoints and collector health.',
      subtitle: 'Validate endpoint coverage, connectivity and collector readiness.'
    },
    users: {
      title: 'Identity and user activity.',
      subtitle: 'Inspect the most relevant user accounts involved in recent activity.'
    },
    logs: {
      title: 'Log stream and forensic context.',
      subtitle: 'Drill into the latest ingested records and correlated telemetry.'
    },
    reports: {
      title: 'Operational reporting and executive insight.',
      subtitle: 'Summarize telemetry trends and support leadership review with reliable KPIs.'
    },
    search: {
      title: 'Search and locate the signal fast.',
      subtitle: 'Query the incidents, alerts and events from one entry point.'
    },
    settings: {
      title: 'Platform controls and response preferences.',
      subtitle: 'Tweak alerting, automation and collector posture for your environment.'
    }
  };

  const current = sectionMap[sectionId] || sectionMap.dashboard;
  if (heroTitle) heroTitle.textContent = current.title;
  if (heroSubtitle) heroSubtitle.textContent = current.subtitle;
  setDashboardVisibility(sectionId === 'dashboard');

  if (sectionId === 'dashboard') {
    await refreshDashboard();
    return;
  }

  await renderSectionContent(sectionId);
  toast(`Viewing ${itemLabel(sectionId)} panel`);
};

const buildKpiCards = (stats) => {
  const grid = document.querySelector('.kpi-grid');
  if (!grid) return;

  const payload = {
    critical_alerts: stats.alerts_by_severity?.[4] || 0,
    high_alerts: stats.alerts_by_severity?.[3] || 0,
    medium_alerts: stats.alerts_by_severity?.[2] || 0,
    low_alerts: stats.alerts_by_severity?.[1] || 0,
    total_events: stats.total_events || 0,
    open_incidents: stats.open_incidents || 0,
    connected_agents: stats.connected_agents || 0,
    detection_rules: stats.detection_rules || 0,
    healthy_agents: stats.healthy_agents || 0,
    events_per_second: stats.events_per_second || 0
  };

  const cards = [
    { key: 'critical_alerts', label: 'Critical alerts', severity: 'critical' },
    { key: 'high_alerts', label: 'High alerts', severity: 'high' },
    { key: 'medium_alerts', label: 'Medium alerts', severity: 'medium' },
    { key: 'total_events', label: 'Total events', severity: 'accent' },
    { key: 'open_incidents', label: 'Open incidents', severity: 'warning' },
    { key: 'connected_agents', label: 'Connected agents', severity: 'success' },
    { key: 'healthy_agents', label: 'Healthy agents', severity: 'success' },
    { key: 'detection_rules', label: 'Detection rules', severity: 'accent' },
    { key: 'events_per_second', label: 'Events / sec', severity: 'medium' }
  ];

  grid.innerHTML = cards.map((card) => `
    <article class="kpi-card ${card.severity}">
      <div class="kpi-label">${card.label}</div>
      <div class="kpi-value">${formatStatValue(payload[card.key])}</div>
      <div class="kpi-sub">Live feed from the monitoring engine</div>
    </article>
  `).join('');
};

const buildAlertsTable = (alerts) => {
  const body = document.querySelector('#alerts-table-body');
  if (!body) return;

  if (!alerts.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">No alerts available yet. Load demo data to preview incident triage.</td></tr>';
    return;
  }

  body.innerHTML = alerts.map((alert) => {
    const severityLabel = { 1: 'Low', 2: 'Medium', 3: 'High', 4: 'Critical' }[alert.severity] || 'Info';
    const severityClass = `badge-${severityLabel.toLowerCase()}`;
    return `
      <tr tabindex="0" data-alert-id="${alert.id}">
        <td>${escapeHtml(alert.timestamp)}</td>
        <td>${escapeHtml(alert.hostname)}</td>
        <td><span class="badge ${severityClass}">${severityLabel}</span></td>
        <td><span class="mitre-tag">${escapeHtml(alert.mitre_technique || '—')}</span></td>
        <td>${escapeHtml(alert.threat_type)}</td>
        <td>${escapeHtml(alert.source_ip || '—')}</td>
      </tr>
    `;
  }).join('');

  body.querySelectorAll('tr').forEach((row) => {
    row.addEventListener('click', () => showAlertDetails(row.dataset.alertId));
    row.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') showAlertDetails(row.dataset.alertId);
    });
  });
};

const buildRecentEventsTable = (events) => {
  const body = document.querySelector('#events-table-body');
  if (!body) return;

  if (!events.length) {
    body.innerHTML = '<tr><td colspan="6" class="empty-state">No events ingested yet.</td></tr>';
    return;
  }

  body.innerHTML = events.map((event) => `
    <tr>
      <td>${escapeHtml(event.timestamp)}</td>
      <td>${escapeHtml(event.hostname)}</td>
      <td>${escapeHtml(event.event_type)}</td>
      <td>${escapeHtml(event.source_ip || '—')}</td>
      <td>${escapeHtml(event.event_id || '—')}</td>
      <td>${escapeHtml(event.username || '—')}</td>
    </tr>
  `).join('');
};

const buildCharts = (stats) => {
  const timelineCtx = document.getElementById('timeline-chart');
  const topIpsCtx = document.getElementById('top-ips-chart');
  const severityCtx = document.getElementById('severity-chart');
  if (!timelineCtx || !topIpsCtx) return;

  const labels = Object.keys(stats.events_per_hour || {}).map((hour) => `${hour}:00`);
  const values = Object.values(stats.events_per_hour || {}).map(Number);
  const topIps = (stats.top_source_ips || []).slice(0, 6);
  const severityLabels = ['Low', 'Medium', 'High', 'Critical'];
  const severityValues = [1, 2, 3, 4].map((level) => stats.alerts_by_severity?.[level] || 0);

  if (window.timelineChart) {
    window.timelineChart.data.labels = labels;
    window.timelineChart.data.datasets[0].data = values;
    window.timelineChart.update();
  } else {
    window.timelineChart = new Chart(timelineCtx, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Events',
          data: values,
          borderColor: '#60a5fa',
          backgroundColor: 'rgba(96, 165, 250, 0.16)',
          fill: true,
          tension: 0.35,
          pointRadius: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#94a3b8' } },
          y: { grid: { color: 'rgba(148, 163, 184, 0.16)' }, ticks: { color: '#94a3b8' } }
        }
      }
    });
  }

  if (window.topIpsChart) {
    window.topIpsChart.data.labels = topIps.map(([label]) => label);
    window.topIpsChart.data.datasets[0].data = topIps.map(([, value]) => value);
    window.topIpsChart.update();
  } else {
    window.topIpsChart = new Chart(topIpsCtx, {
      type: 'bar',
      data: {
        labels: topIps.map(([label]) => label),
        datasets: [{
          label: 'Events',
          data: topIps.map(([, value]) => value),
          backgroundColor: ['#60a5fa', '#34d399', '#fbbf24', '#fb7185', '#22d3ee', '#c084fc'],
          borderRadius: 10,
          maxBarThickness: 28
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#94a3b8' } },
          y: { grid: { color: 'rgba(148, 163, 184, 0.16)' }, ticks: { color: '#94a3b8' } }
        }
      }
    });
  }

  if (severityCtx) {
    if (window.severityChart) {
      window.severityChart.data.datasets[0].data = severityValues;
      window.severityChart.update();
    } else {
      window.severityChart = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
          labels: severityLabels,
          datasets: [{
            data: severityValues,
            backgroundColor: ['#60a5fa', '#7c9cff', '#fbbf24', '#fb7185'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '68%',
          plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 10 } } }
        }
      });
    }
  }
};

const renderSystemStatus = (status) => {
  const target = document.querySelector('#sidebar-system');
  if (!target) return;
  const data = status.data || {};
  const collector = data.collector_active ? 'Collector online' : 'Collector offline';
  target.innerHTML = `
    <span><strong>Host:</strong> ${escapeHtml(data.hostname || 'unknown')}</span>
    <span><strong>Platform:</strong> ${escapeHtml(data.platform || 'unknown')}</span>
    <span><strong>Uptime:</strong> ${Math.round((data.uptime_seconds || 0) / 60)} min</span>
    <span><strong>Status:</strong> ${escapeHtml(collector)}</span>
  `;
};

const showAlertDetails = (alertId) => {
  fetch(`${endpoints.alerts}?limit=10&page=1`)
    .then((response) => response.json())
    .then((payload) => {
      const alert = (payload.data || []).find((item) => String(item.id) === String(alertId));
      if (!alert) {
        toast('Alert details not found');
        return;
      }
      openRightPanel(`
        <h3>Alert ${alert.id}</h3>
        <p><strong>Severity:</strong> ${alert.severity_name || 'Info'}</p>
        <p><strong>Threat type:</strong> ${alert.threat_type}</p>
        <p><strong>Host:</strong> ${alert.hostname}</p>
        <p><strong>Source IP:</strong> ${alert.source_ip || '—'}</p>
        <p><strong>Assigned:</strong> ${alert.assigned_analyst || 'Unassigned'}</p>
        <hr />
        <pre>${alert.description}</pre>
      `);
    })
    .catch(() => toast('Failed to load alert details'));
};

const openRightPanel = (html) => {
  let panel = document.querySelector('.right-panel');
  if (!panel) {
    panel = document.createElement('aside');
    panel.className = 'right-panel';
    document.querySelector('.screen')?.appendChild(panel);
  }
  panel.innerHTML = `<div class="panel-inner">${html}<button class="close-panel" type="button">Close</button></div>`;
  panel.querySelector('.close-panel').addEventListener('click', () => panel.remove());
};

const toast = (text, timeout = 4000) => {
  let root = document.querySelector('.toast-container');
  if (!root) {
    root = document.createElement('div');
    root.className = 'toast-container';
    document.body.appendChild(root);
  }
  const item = document.createElement('div');
  item.className = 'toast';
  item.textContent = text;
  root.appendChild(item);
  setTimeout(() => item.remove(), timeout);
};

const fetchStats = async () => {
  const response = await fetch(endpoints.stats);
  if (!response.ok) throw new Error('Failed to load stats');
  return response.json();
};

const fetchAlerts = async () => {
  const response = await fetch(`${endpoints.alerts}?limit=12&page=1`);
  if (!response.ok) throw new Error('Failed to load alerts');
  return response.json();
};

const fetchRecentEvents = async () => {
  const response = await fetch(`${endpoints.recentEvents}?limit=12`);
  if (!response.ok) throw new Error('Failed to load recent events');
  return response.json();
};

const fetchSystemStatus = async () => {
  const response = await fetch(endpoints.systemStatus);
  if (!response.ok) throw new Error('Failed to load system status');
  return response.json();
};

const fetchDetectionRules = async () => {
  const response = await fetch(endpoints.detectionRules);
  if (!response.ok) throw new Error('Failed to load detection rules');
  return response.json();
};

const fetchThreatSummary = async () => {
  const response = await fetch(endpoints.threatSummary);
  if (!response.ok) throw new Error('Failed to load threat summary');
  return response.json();
};

const renderDashboard = async () => {
  const [statsData, alertsData, eventsData, systemStatusData, rulesData, threatData] = await Promise.all([
    fetchStats(),
    fetchAlerts(),
    fetchRecentEvents(),
    fetchSystemStatus(),
    fetchDetectionRules().catch(() => ({ data: [] })),
    fetchThreatSummary().catch(() => ({ data: {} }))
  ]);

  state.stats = statsData.data || {};
  state.alerts = alertsData.data || [];
  state.events = eventsData.data || [];
  state.systemStatus = systemStatusData.data || {};
  state.detectionRules = rulesData.data || [];
  state.threatSummary = threatData.data || {};

  buildKpiCards(state.stats);
  buildAlertsTable(state.alerts);
  buildRecentEventsTable(state.events);
  buildCharts(state.stats);
  renderSystemStatus(systemStatusData);
  renderRiskScore(state.stats);
  renderActivityTrack(state.events, state.alerts);
  renderEmptyBanner(state.stats);
  updateAlertBadge(state.alerts);

  const last = document.querySelector('#lastUpdate');
  if (last) {
    last.textContent = `Last update: ${new Date().toLocaleTimeString()}`;
  }
};

const refreshDashboard = async () => {
  const button = document.querySelector('#refresh-dashboard');
  if (button) {
    button.disabled = true;
    button.textContent = 'Refreshing…';
  }
  try {
    await renderDashboard();
    toast('Dashboard refreshed successfully');
  } catch (error) {
    toast('Unable to refresh dashboard');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Refresh data';
    }
  }
};

const acknowledgeAlert = async (alertId) => {
  const response = await fetch('/api/alerts/acknowledge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ alert_id: Number(alertId) })
  });
  if (!response.ok) throw new Error('Failed to acknowledge alert');
  state.alerts = state.alerts.filter((alert) => String(alert.id) !== String(alertId));
  await renderSectionContent('alerts');
  toast('Alert acknowledged');
};

const renderSectionContent = async (sectionId) => {
  const contentRoot = document.getElementById('section-content');
  if (!contentRoot) return;

  if (sectionId === 'dashboard') {
    contentRoot.innerHTML = '';
    return;
  }

  const stats = state.stats || {};
  const alerts = state.alerts || [];
  const events = state.events || [];
  const systemStatus = state.systemStatus || {};

  if (!Object.keys(stats).length || !alerts.length && !events.length) {
    await renderDashboard();
  }

  switch (sectionId) {
    case 'security-events': {
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar">
            <div>
              <h3>Security event stream</h3>
              <p>Live events correlated with host, source IP and user context.</p>
            </div>
            <button class="button small" type="button" onclick="window.location.reload()">Reload feed</button>
          </div>
          <div class="section-grid">
            <div class="metric-card">
              <strong>${formatStatValue(stats.total_events || 0)}</strong>
              <span>Total events ingested</span>
            </div>
            <div class="metric-card">
              <strong>${formatStatValue(stats.events_per_second || 0)}</strong>
              <span>Events per second</span>
            </div>
          </div>
          <div class="table-scroll">
            <table class="table small">
              <thead><tr><th>Timestamp</th><th>Host</th><th>Event type</th><th>Source IP</th><th>User</th></tr></thead>
              <tbody>${events.slice(0, 10).map((event) => `<tr><td>${escapeHtml(event.timestamp)}</td><td>${escapeHtml(event.hostname)}</td><td>${escapeHtml(event.event_type)}</td><td>${escapeHtml(event.source_ip || '—')}</td><td>${escapeHtml(event.username || '—')}</td></tr>`).join('')}</tbody>
            </table>
          </div>
        </section>
      `;
      break;
    }
    case 'alerts': {
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar">
            <div>
              <h3>Alert queue</h3>
              <p>Prioritize the most critical detections and respond quickly.</p>
            </div>
            <button class="button small secondary" type="button" data-refresh-alerts>Refresh</button>
          </div>
          <div class="section-list">
            ${alerts.length ? alerts.map((alert) => `
              <div class="section-list-item">
                <div>
                  <strong>${escapeHtml(alert.threat_type)}</strong>
                  <span>${escapeHtml(alert.hostname)} · ${escapeHtml(alert.timestamp)}</span>
                </div>
                <div style="display:flex;gap:8px;align-items:center;">
                  <span class="status-chip ${alert.severity >= 3 ? 'warn' : 'info'}">${escapeHtml(alert.severity_name || 'Info')}</span>
                  <button class="button small secondary" type="button" data-ack-alert="${alert.id}">Acknowledge</button>
                </div>
              </div>
            `).join('') : '<div class="empty-state">No active alerts right now.</div>'}
          </div>
        </section>
      `;
      contentRoot.querySelectorAll('[data-ack-alert]').forEach((button) => {
        button.addEventListener('click', async () => {
          try {
            await acknowledgeAlert(button.dataset.ackAlert);
          } catch (error) {
            toast('Unable to acknowledge alert');
          }
        });
      });
      contentRoot.querySelector('[data-refresh-alerts]')?.addEventListener('click', async () => {
        try {
          const refreshed = await fetchAlerts();
          state.alerts = refreshed.data || [];
          await renderSectionContent('alerts');
          toast('Alert queue refreshed');
        } catch (error) {
          toast('Unable to refresh alerts');
        }
      });
      break;
    }
    case 'incidents': {
      const incidentCount = Math.max(1, Number(stats.open_incidents || 0));
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar">
            <div>
              <h3>Active incidents</h3>
              <p>${incidentCount} incident${incidentCount === 1 ? '' : 's'} currently tracked by the SOC workflow.</p>
            </div>
            <button class="button small" type="button" data-escalate>Escalate review</button>
          </div>
          <div class="section-grid three">
            <div class="metric-card"><strong>${formatStatValue(stats.open_incidents || 0)}</strong><span>Open incidents</span></div>
            <div class="metric-card"><strong>${formatStatValue(stats.critical_alerts || 0)}</strong><span>Critical alerts linked</span></div>
            <div class="metric-card"><strong>${formatStatValue(stats.connected_agents || 0)}</strong><span>Monitoring sources</span></div>
          </div>
          <div class="section-list">
            ${alerts.slice(0, 6).map((alert) => `
              <div class="section-list-item">
                <div>
                  <strong>${escapeHtml(alert.threat_type)}</strong>
                  <span>${escapeHtml(alert.hostname)} · ${escapeHtml(alert.timestamp)}</span>
                </div>
                <span class="status-chip warn">${escapeHtml(alert.severity_name || 'Priority')}</span>
              </div>
            `).join('')}
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-escalate]')?.addEventListener('click', () => {
        toast('Incident review escalated to the response team');
      });
      break;
    }
    case 'threat-detection': {
      const threatSummary = state.threatSummary || {};
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar">
            <div>
              <h3>Threat detection posture</h3>
              <p>Real-time signal quality and detection coverage.</p>
            </div>
            <button class="button small" type="button" data-run-scan>Run detection scan</button>
          </div>
          <div class="section-grid">
            <div class="metric-card"><strong>${formatStatValue(threatSummary.total_alerts || 0)}</strong><span>Total threat summaries</span></div>
            <div class="metric-card"><strong>${formatStatValue(stats.detection_rules || 0)}</strong><span>Active detection rules</span></div>
          </div>
          <div class="section-list">
            ${(state.detectionRules || []).slice(0, 6).map((rule) => `
              <div class="section-list-item">
                <div>
                  <strong>${escapeHtml(rule.name)}</strong>
                  <span>${escapeHtml(rule.description || 'No description available')}</span>
                </div>
                <span class="status-chip ${rule.severity === 'High' || rule.severity === 'Critical' ? 'warn' : 'info'}">${escapeHtml(rule.severity)}</span>
              </div>
            `).join('')}
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-run-scan]')?.addEventListener('click', () => {
        toast('Detection scan completed for the latest telemetry window');
      });
      break;
    }
    case 'detection-rules': {
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar">
            <div>
              <h3>Detection rules</h3>
              <p>Review the rule catalog and tune the response posture.</p>
            </div>
            <button class="button small secondary" type="button" data-refresh-rules>Refresh rules</button>
          </div>
          <div class="section-list">
            ${(state.detectionRules || []).map((rule) => `
              <div class="section-list-item">
                <div>
                  <strong>${escapeHtml(rule.name)}</strong>
                  <span>${escapeHtml(rule.description || 'No description available')}</span>
                </div>
                <div style="display:flex;gap:8px;align-items:center;">
                  <span class="status-chip ${rule.severity === 'High' || rule.severity === 'Critical' ? 'warn' : 'info'}">${escapeHtml(rule.severity)}</span>
                  <button class="button small secondary" type="button" data-rule-detail="${escapeHtml(rule.name)}">Inspect</button>
                </div>
              </div>
            `).join('')}
          </div>
        </section>
      `;
      contentRoot.querySelectorAll('[data-rule-detail]').forEach((button) => {
        button.addEventListener('click', () => {
          openRightPanel(`<h3>${button.dataset.ruleDetail}</h3><p>Rule inspection is active and ready for tuning.</p>`);
        });
      });
      contentRoot.querySelector('[data-refresh-rules]')?.addEventListener('click', async () => {
        try {
          const rulesData = await fetchDetectionRules();
          state.detectionRules = rulesData.data || [];
          await renderSectionContent('detection-rules');
          toast('Detection rules refreshed');
        } catch (error) {
          toast('Unable to refresh detection rules');
        }
      });
      break;
    }
    case 'assets': {
      const assetItems = [
        { name: 'Identity store', status: 'Healthy', detail: '96% monitoring coverage' },
        { name: 'Core servers', status: 'Watch', detail: '3 alerts queued' },
        { name: 'Cloud workloads', status: 'Healthy', detail: 'All collectors online' }
      ];
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar">
            <div><h3>Critical assets</h3><p>Operational readiness for the most important infrastructure resources.</p></div>
            <button class="button small" type="button" data-run-asset-scan>Run asset scan</button>
          </div>
          <div class="section-list">
            ${assetItems.map((item) => `
              <div class="section-list-item">
                <div><strong>${escapeHtml(item.name)}</strong><span>${escapeHtml(item.detail)}</span></div>
                <span class="status-chip ${item.status === 'Healthy' ? 'good' : 'warn'}">${escapeHtml(item.status)}</span>
              </div>
            `).join('')}
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-run-asset-scan]')?.addEventListener('click', () => {
        toast('Asset scan completed successfully');
      });
      break;
    }
    case 'endpoints': {
      const endpointItems = (systemStatus.collector_channels || []).map((channel) => ({ name: channel, status: 'Online' }));
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar"><div><h3>Endpoints and collectors</h3><p>Endpoint coverage and collector health.</p></div><button class="button small secondary" type="button" data-check-endpoints>Check endpoints</button></div>
          <div class="section-list">
            ${endpointItems.length ? endpointItems.map((item) => `
              <div class="section-list-item">
                <div><strong>${escapeHtml(item.name)}</strong><span>Collector channel available</span></div>
                <span class="status-chip good">${escapeHtml(item.status)}</span>
              </div>
            `).join('') : '<div class="empty-state">No endpoint sources are currently registered.</div>'}
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-check-endpoints]')?.addEventListener('click', () => {
        toast('Endpoint check completed');
      });
      break;
    }
    case 'users': {
      const userItems = [...new Set(events.map((event) => event.username).filter(Boolean))].slice(0, 6);
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar"><div><h3>User activity</h3><p>Accounts that appear in the latest telemetry.</p></div><button class="button small" type="button" data-review-users>Review users</button></div>
          <div class="section-list">
            ${userItems.length ? userItems.map((user) => `
              <div class="section-list-item">
                <div><strong>${escapeHtml(user)}</strong><span>Observed in the latest security events</span></div>
                <span class="status-chip info">Active</span>
              </div>
            `).join('') : '<div class="empty-state">No distinct users have been observed yet.</div>'}
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-review-users]')?.addEventListener('click', () => {
        toast('User review panel opened');
      });
      break;
    }
    case 'logs': {
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar"><div><h3>Log stream</h3><p>Recent records from the ingest pipeline.</p></div><button class="button small secondary" type="button" data-filter-logs>Filter logs</button></div>
          <div class="table-scroll">
            <table class="table small">
              <thead><tr><th>Timestamp</th><th>Host</th><th>Event type</th><th>Message</th></tr></thead>
              <tbody>${events.slice(0, 10).map((event) => `<tr><td>${escapeHtml(event.timestamp)}</td><td>${escapeHtml(event.hostname)}</td><td>${escapeHtml(event.event_type)}</td><td>${escapeHtml(event.message || '—')}</td></tr>`).join('')}</tbody>
            </table>
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-filter-logs]')?.addEventListener('click', () => {
        toast('Log filter applied to the latest records');
      });
      break;
    }
    case 'reports': {
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar"><div><h3>Executive reports</h3><p>High-level summaries for leadership and operational stakeholders.</p></div><button class="button small" type="button" data-export-report>Export summary</button></div>
          <div class="section-grid three">
            <div class="metric-card"><strong>${formatStatValue(stats.total_events || 0)}</strong><span>Ingested events</span></div>
            <div class="metric-card"><strong>${formatStatValue(stats.open_incidents || 0)}</strong><span>Open incidents</span></div>
            <div class="metric-card"><strong>${formatStatValue(stats.connected_agents || 0)}</strong><span>Connected sensors</span></div>
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-export-report]')?.addEventListener('click', () => {
        toast('Executive summary exported');
      });
      break;
    }
    case 'search': {
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar"><div><h3>Search console</h3><p>Search across the current alert and event context.</p></div></div>
          <div class="search-row">
            <input id="search-query" type="text" placeholder="Search events, hosts, IPs or threat names" />
            <button class="button small" type="button" data-run-search>Search</button>
          </div>
          <div class="section-list">
            ${events.slice(0, 6).map((event) => `
              <div class="section-list-item">
                <div><strong>${escapeHtml(event.event_type)}</strong><span>${escapeHtml(event.hostname)} · ${escapeHtml(event.source_ip || '—')}</span></div>
                <span class="status-chip info">Match candidate</span>
              </div>
            `).join('')}
          </div>
        </section>
      `;
      contentRoot.querySelector('[data-run-search]')?.addEventListener('click', () => {
        const input = contentRoot.querySelector('#search-query');
        toast(input && input.value ? `Search started for “${input.value}”` : 'Please enter a search term');
      });
      break;
    }
    case 'settings': {
      contentRoot.innerHTML = `
        <section class="section-card">
          <div class="section-toolbar"><div><h3>Platform settings</h3><p>Control the operational behavior of the SOC environment.</p></div><button class="button small" type="button" data-save-settings>Save</button></div>
          <div class="metric-stack">
            <div class="toggle-row"><div><strong>Notification routing</strong><span>Send updates to the configured channels.</span></div><button class="button small secondary" type="button" data-toggle="notifications">${state.settings.notifications ? 'Enabled' : 'Disabled'}</button></div>
            <div class="toggle-row"><div><strong>Auto triage</strong><span>Automatically prioritize new alerts.</span></div><button class="button small secondary" type="button" data-toggle="autoTriage">${state.settings.autoTriage ? 'Enabled' : 'Disabled'}</button></div>
            <div class="toggle-row"><div><strong>Collector mode</strong><span>Switch between observe and escalate modes.</span></div><button class="button small secondary" type="button" data-toggle="collectorMode">${escapeHtml(state.settings.collectorMode)}</button></div>
          </div>
        </section>
      `;
      contentRoot.querySelectorAll('[data-toggle]').forEach((button) => {
        button.addEventListener('click', () => {
          const key = button.dataset.toggle;
          if (key === 'collectorMode') {
            state.settings.collectorMode = state.settings.collectorMode === 'observe' ? 'escalate' : 'observe';
          } else {
            state.settings[key] = !state.settings[key];
          }
          renderSectionContent('settings');
        });
      });
      contentRoot.querySelector('[data-save-settings]')?.addEventListener('click', () => {
        toast('Settings saved');
      });
      break;
    }
    default:
      contentRoot.innerHTML = '<section class="section-card"><div class="empty-state">This section is available.</div></section>';
  }
};

const loadDemoData = async () => {
  const response = await fetch(endpoints.demoSeed, { method: 'POST' });
  if (!response.ok) throw new Error('Failed to load demo data');
  await renderDashboard();
  toast('Demo telemetry loaded — enterprise preview ready');
};

const init = () => {
  renderNav();
  updateSection('dashboard').catch(() => toast('Unable to load dashboard data'));

  document.querySelector('.nav-list')?.addEventListener('click', (event) => {
    const button = event.target.closest('[data-section]');
    if (!button) return;
    updateSection(button.dataset.section).catch(() => toast('Unable to load section data'));
  });

  document.querySelector('#refresh-dashboard')?.addEventListener('click', () => {
    refreshDashboard();
  });

  document.querySelector('#load-demo-data')?.addEventListener('click', () => {
    loadDemoData().catch(() => toast('Unable to load demo data'));
  });

  document.querySelector('#alert-bell')?.addEventListener('click', () => {
    updateSection('alerts').catch(() => toast('Unable to open alerts'));
  });

  document.querySelectorAll('[data-nav]').forEach((button) => {
    button.addEventListener('click', () => updateSection(button.dataset.nav));
  });

  document.querySelector('#global-search')?.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      updateSection('search').then(() => {
        const input = document.querySelector('#search-query');
        if (input) input.value = event.target.value;
      });
    }
  });
};

window.addEventListener('DOMContentLoaded', init);
