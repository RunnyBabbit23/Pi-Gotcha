// Pi-Gotcha dashboard

const REFRESH_MS = 5000;
let domainsChart = null;
let map          = null;
let markers      = [];

// ── Clock ──────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById("clock").textContent = new Date().toLocaleString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Helpers ────────────────────────────────────────────────────────────
async function apiFetch(path) {
  const r = await fetch(path);
  return r.json();
}

function fmt(ts) {
  return new Date(ts + "Z").toLocaleTimeString();
}

// ── Stats ──────────────────────────────────────────────────────────────
async function refreshStats() {
  const s = await apiFetch("/api/stats/");
  document.getElementById("total-queries").textContent   = s.total_queries.toLocaleString();
  document.getElementById("blocked-queries").textContent = s.blocked_queries.toLocaleString();
  document.getElementById("block-percent").textContent   = s.block_percent + "%";
  document.getElementById("total-devices").textContent   = s.total_devices;
  document.getElementById("blocklist-size").textContent  = s.blocklist_size;
}

// ── DNS Feed ───────────────────────────────────────────────────────────
async function refreshDNS() {
  const rows  = await apiFetch("/api/dns/queries?limit=50");
  const tbody = document.querySelector("#dns-table tbody");
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${fmt(r.timestamp)}</td>
      <td>${r.client_ip}</td>
      <td>${r.domain}</td>
      <td class="${r.blocked ? "badge-blocked" : "badge-allowed"}">${r.blocked ? "BLOCKED" : "OK"}</td>
      <td>${r.blocked
        ? `<button class="danger" onclick="unblock('${r.domain}')">Unblock</button>`
        : `<button onclick="quickBlock('${r.domain}')">Block</button>`
      }</td>`;
    tbody.appendChild(tr);
  }
}

// ── Top Domains Chart ──────────────────────────────────────────────────
async function refreshDomainsChart() {
  const data   = await apiFetch("/api/dns/top-domains?limit=10");
  const labels = data.map(d => d.domain);
  const counts = data.map(d => d.count);

  if (domainsChart) {
    domainsChart.data.labels        = labels;
    domainsChart.data.datasets[0].data = counts;
    domainsChart.update();
    return;
  }

  domainsChart = new Chart(document.getElementById("domains-chart"), {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Queries",
        data: counts,
        backgroundColor: "#58a6ff88",
        borderColor: "#58a6ff",
        borderWidth: 1,
      }]
    },
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" } },
        y: { ticks: { color: "#c9d1d9" }, grid: { color: "#30363d" } },
      }
    }
  });
}

// ── Traffic Map ────────────────────────────────────────────────────────
function initMap() {
  map = L.map("map").setView([20, 0], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors",
    maxZoom: 18,
  }).addTo(map);
}

async function refreshMap() {
  const data = await apiFetch("/api/traffic/top-destinations?limit=50");
  markers.forEach(m => m.remove());
  markers = [];
  for (const d of data) {
    const g = d.geo;
    if (!g || !g.latitude) continue;
    const m = L.circleMarker([g.latitude, g.longitude], {
      radius: Math.min(4 + Math.log(d.connections + 1) * 3, 20),
      color: "#f85149",
      fillColor: "#f8514988",
      fillOpacity: 0.7,
    }).addTo(map);
    m.bindPopup(`<b>${d.dst_ip}</b><br>${g.city || ""}, ${g.country || ""}<br>${d.connections} connections`);
    markers.push(m);
  }
}

// ── Blocklist ──────────────────────────────────────────────────────────
async function refreshBlocklist() {
  const rows  = await apiFetch("/api/blocklist/");
  const tbody = document.querySelector("#blocklist-table tbody");
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.domain}</td>
      <td>${r.reason || ""}</td>
      <td>${fmt(r.added_at)}</td>
      <td><button class="danger" onclick="unblock('${r.domain}')">Remove</button></td>`;
    tbody.appendChild(tr);
  }
}

async function blockDomain() {
  const domain = document.getElementById("block-input").value.trim();
  const reason = document.getElementById("block-reason").value.trim();
  if (!domain) return;
  await fetch("/api/blocklist/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, reason })
  });
  document.getElementById("block-input").value  = "";
  document.getElementById("block-reason").value = "";
  refreshAll();
}

async function quickBlock(domain) {
  await fetch("/api/blocklist/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, reason: "Manual block from feed" })
  });
  refreshAll();
}

async function unblock(domain) {
  await fetch(`/api/blocklist/${encodeURIComponent(domain)}`, { method: "DELETE" });
  refreshAll();
}

// ── Devices ────────────────────────────────────────────────────────────
async function refreshDevices() {
  const rows  = await apiFetch("/api/devices/");
  const tbody = document.querySelector("#devices-table tbody");
  tbody.innerHTML = "";
  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.ip}</td>
      <td>${r.mac || "—"}</td>
      <td>${fmt(r.last_seen)}</td>`;
    tbody.appendChild(tr);
  }
}

// ── Refresh all ────────────────────────────────────────────────────────
async function refreshAll() {
  await Promise.all([
    refreshStats(),
    refreshDNS(),
    refreshDomainsChart(),
    refreshMap(),
    refreshBlocklist(),
    refreshDevices(),
  ]);
}

// ── Init ───────────────────────────────────────────────────────────────
initMap();
refreshAll();
setInterval(refreshAll, REFRESH_MS);
