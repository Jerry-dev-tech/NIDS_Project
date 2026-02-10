let alertChart;
const MAX_POINTS = 30;

function initAlertChart() {
  const ctx = document.getElementById('alertChart').getContext('2d');
  alertChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Total Alerts',
        data: [],
        fill: true,
        tension: 0.2,
        backgroundColor: 'rgba(66,133,244,0.08)',
        borderColor: '#4285f4',
        pointRadius: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { beginAtZero: true, suggestedMax: 10 },
        x: { ticks: { maxRotation: 0, autoSkip: true } }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

// render protocol counters
function renderProtocolCounts(protocols) {
  const container = document.getElementById('protocolCards');
  container.innerHTML = '';
  const protOrder = ['TCP','UDP','ICMP','OTHER'];
  protOrder.forEach(p => {
    const count = protocols[p] || 0;
    const el = document.createElement('div');
    el.className = 'proto-card';
    el.innerHTML = `<div class="proto-name">${p}</div><div class="proto-count">${count}</div>`;
    container.appendChild(el);
  });
}

// render severity badges
function renderSeverityCounts(severities) {
  document.getElementById('sev-low').innerText = severities['low'] || 0;
  document.getElementById('sev-med').innerText = severities['medium'] || 0;
  document.getElementById('sev-high').innerText = severities['high'] || 0;
}

// update top alert types
function renderTopTypes(types) {
  const el = document.getElementById('topTypes');
  el.innerHTML = '';
  const entries = Object.entries(types).sort((a,b) => b[1]-a[1]).slice(0,5);
  if(entries.length === 0){
    el.innerHTML = '<em>No alert types yet</em>';
    return;
  }
  entries.forEach(([t,c]) => {
    const r = document.createElement('div');
    r.className = 'type-row';
    r.innerHTML = `<span class="type-name">${t}</span><span class="type-count">${c}</span>`;
    el.appendChild(r);
  });
}

// fetch stats
async function fetchStats() {
  try {
    const resp = await fetch('/stats');
    const data = await resp.json();
    renderProtocolCounts(data.protocols || {});
    renderSeverityCounts(data.severities || {});
    renderTopTypes(data.types || {});
    setConnected(true);
  } catch (e) {
    setConnected(false);
  }
}

function setConnected(yes) {
  const el = document.getElementById('status');
  el.innerText = yes ? 'Status: connected' : 'Status: disconnected';
  el.className = yes ? 'status connected' : 'status disconnected';
}

// render alerts table
function renderAlerts(data, filterProto) {
  const tbody = document.getElementById('alerts_tbody');
  tbody.innerHTML = '';
  const arr = (data.alerts || []).slice(0,200);
  arr.forEach(a => {
    if(filterProto && filterProto !== 'All' && a.proto !== filterProto) return;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="small">${a.time}</td>
      <td>${a.proto}</td>
      <td>${a.src} → ${a.dst}</td>
      <td>${a.type}</td>
      <td><span class="severity ${a.severity}">${a.severity}</span></td>
      <td class="message-col">${a.message}</td>
    `;
    tbody.appendChild(tr);
  });
  // update chart
  const nowLabel = new Date().toLocaleTimeString();
  alertChart.data.labels.push(nowLabel);
  alertChart.data.datasets[0].data.push(data.count || 0);
  if (alertChart.data.labels.length > 30) {
    alertChart.data.labels.shift();
    alertChart.data.datasets[0].data.shift();
  }
  alertChart.update();
}

async function fetchAlertsAndUpdate() {
  const filterProto = document.getElementById('protocolFilter').value;
  try {
    const resp = await fetch('/alerts');
    const data = await resp.json();
    renderAlerts(data, filterProto);
    document.getElementById('totalCount').innerText = data.count || 0;
    setConnected(true);
  } catch (e) {
    setConnected(false);
  }
}

async function clearAlerts() {
  await fetch('/clear', { method: 'POST' });
  // refresh UI
  fetchAlertsAndUpdate();
  fetchStats();
}

window.addEventListener('load', () => {
  initAlertChart();
  // initial fetch
  fetchStats();
  fetchAlertsAndUpdate();
  // pollers
  setInterval(fetchStats, 3000);
  setInterval(fetchAlertsAndUpdate, 2000);

  // hook filter
  document.getElementById('protocolFilter').addEventListener('change', () => {
    fetchAlertsAndUpdate();
  });
  document.getElementById('btnClear').addEventListener('click', clearAlerts);
});
