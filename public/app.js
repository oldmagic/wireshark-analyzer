// State
let currentPage = 1;
const packetsPerPage = 100;
let charts = {};
// Store conversations data globally for modal access
let conversationsData = [];

// DOM Elements
const uploadBox = document.getElementById("uploadBox");
const fileInput = document.getElementById("fileInput");
const uploadSection = document.getElementById("uploadSection");
const mainContent = document.getElementById("mainContent");
const progressContainer = document.getElementById("progressContainer");
const progressFill = document.getElementById("progressFill");
const progressPercent = document.getElementById("progressPercent");
const progressText = document.getElementById("progressText");

// File Upload Handlers
document.getElementById("selectFileBtn").addEventListener("click", (e) => {
  e.stopPropagation();
  fileInput.click();
});

uploadBox.addEventListener("click", (e) => {
  if (e.target === uploadBox || e.target.closest(".upload-box")) {
    fileInput.click();
  }
});

uploadBox.addEventListener("dragover", (e) => {
  e.preventDefault();
  uploadBox.classList.add("dragover");
});

uploadBox.addEventListener("dragleave", () => {
  uploadBox.classList.remove("dragover");
});

uploadBox.addEventListener("drop", (e) => {
  e.preventDefault();
  uploadBox.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) handleFileUpload(file);
});

fileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) {
    handleFileUpload(file);
  }
  // Reset input so the same file can be selected again if needed
  e.target.value = "";
});
async function handleFileUpload(file) {
  if (!file.name.endsWith(".txt")) {
    alert("Please upload a .txt file exported from Wireshark");
    return;
  }

  uploadBox.hidden = true;
  progressContainer.hidden = false;

  const formData = new FormData();
  formData.append("capture", file);

  // Start progress polling
  const progressInterval = setInterval(async () => {
    try {
      const res = await fetch("/api/progress");
      const data = await res.json();
      updateProgress(data.progress);
    } catch (e) {}
  }, 500);

  try {
    progressText.textContent = `Uploading ${file.name}...`;

    const response = await fetch("/api/upload", {
      method: "POST",
      body: formData,
    });

    clearInterval(progressInterval);

    if (!response.ok) {
      throw new Error("Upload failed");
    }

    const result = await response.json();
    updateProgress(100);
    progressText.textContent = "Analysis complete!";

    setTimeout(() => {
      uploadSection.hidden = true;
      mainContent.hidden = false;
      loadAllData();
    }, 500);
  } catch (error) {
    clearInterval(progressInterval);
    alert("Error: " + error.message);
    uploadBox.hidden = false;
    progressContainer.hidden = true;
  }
}

function updateProgress(percent) {
  progressFill.style.width = percent + "%";
  progressPercent.textContent = percent + "%";
}

// Tab Navigation
document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));

    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
  });
});

// Load All Data
async function loadAllData() {
  await Promise.all([
    loadSummary(),
    loadPackets(),
    loadProtocols(),
    loadConversations(),
    loadTimeline(),
  ]);
}

// Load Summary
async function loadSummary() {
  try {
    const res = await fetch("/api/summary");
    const data = await res.json();

    document.getElementById("totalPackets").textContent = formatNumber(data.totalPackets);
    document.getElementById("totalBytes").textContent = formatBytes(data.totalBytes);
    document.getElementById("uniqueIPs").textContent = formatNumber(data.uniqueIPs);
    document.getElementById("protocolCount").textContent = data.protocolStats.length;

    document.getElementById("headerStats").innerHTML = `
      <span>📦 ${formatNumber(data.totalPackets)} packets</span>
      <span>💾 ${formatBytes(data.totalBytes)}</span>
      <span>🕐 ${data.startTime || "N/A"}</span>
    `;

    // Populate protocol filter
    const protocolFilter = document.getElementById("protocolFilter");
    data.protocolStats.forEach((p) => {
      const option = document.createElement("option");
      option.value = p.protocol;
      option.textContent = `${p.protocol} (${p.count})`;
      protocolFilter.appendChild(option);
    });

    // Create charts
    createProtocolChart(data.protocolStats);
    createTalkersChart(data.topTalkers);
  } catch (error) {
    console.error("Error loading summary:", error);
  }
}

// Create Protocol Pie Chart
function createProtocolChart(stats) {
  const ctx = document.getElementById("protocolChart").getContext("2d");
  const top10 = stats.slice(0, 10);

  const colors = [
    "#58a6ff",
    "#3fb950",
    "#a371f7",
    "#d29922",
    "#f85149",
    "#39c5cf",
    "#db61a2",
    "#768390",
    "#57ab5a",
    "#c69026",
  ];

  if (charts.protocol) charts.protocol.destroy();

  charts.protocol = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: top10.map((p) => p.protocol),
      datasets: [
        {
          data: top10.map((p) => p.count),
          backgroundColor: colors,
          borderColor: "#0d1117",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          position: "right",
          labels: { color: "#e6edf3", padding: 12 },
        },
      },
    },
  });
}

// Create Top Talkers Bar Chart
function createTalkersChart(talkers) {
  const ctx = document.getElementById("talkersChart").getContext("2d");
  const top10 = talkers.slice(0, 10);

  if (charts.talkers) charts.talkers.destroy();

  charts.talkers = new Chart(ctx, {
    type: "bar",
    data: {
      labels: top10.map((t) => truncate(t.ip, 20)),
      datasets: [
        {
          label: "Sent",
          data: top10.map((t) => t.sent),
          backgroundColor: "#58a6ff",
        },
        {
          label: "Received",
          data: top10.map((t) => t.received),
          backgroundColor: "#3fb950",
        },
      ],
    },
    options: {
      responsive: true,
      indexAxis: "y",
      plugins: {
        legend: { labels: { color: "#e6edf3" } },
      },
      scales: {
        x: {
          stacked: true,
          ticks: { color: "#8b949e" },
          grid: { color: "#21262d" },
        },
        y: {
          stacked: true,
          ticks: { color: "#8b949e" },
          grid: { color: "#21262d" },
        },
      },
    },
  });
}

// Load Packets
async function loadPackets(page = 1) {
  currentPage = page;
  const filter = document.getElementById("packetFilter").value;
  const protocol = document.getElementById("protocolFilter").value;

  try {
    const res = await fetch(
      `/api/packets?page=${page}&limit=${packetsPerPage}&filter=${encodeURIComponent(filter)}&protocol=${encodeURIComponent(protocol)}`
    );
    const data = await res.json();

    const tbody = document.getElementById("packetTableBody");
    tbody.innerHTML = data.packets
      .map(
        (p) => `
      <tr onclick="showPacketDetails(${p.number})">
        <td>${p.number}</td>
        <td>${p.time || "-"}</td>
        <td>${p.source || "-"}</td>
        <td>${p.destination || "-"}</td>
        <td><span class="protocol-badge protocol-${p.protocol}">${p.protocol}</span></td>
        <td>${p.length}</td>
        <td>${truncate(p.info, 60)}</td>
      </tr>
    `
      )
      .join("");

    renderPagination(data.total, data.page, data.totalPages);
  } catch (error) {
    console.error("Error loading packets:", error);
  }
}

function renderPagination(total, current, totalPages) {
  const container = document.getElementById("pagination");
  let html = `<button onclick="loadPackets(1)" ${current === 1 ? "disabled" : ""}>« First</button>`;
  html += `<button onclick="loadPackets(${current - 1})" ${current === 1 ? "disabled" : ""}>‹ Prev</button>`;

  const start = Math.max(1, current - 2);
  const end = Math.min(totalPages, current + 2);

  for (let i = start; i <= end; i++) {
    html += `<button onclick="loadPackets(${i})" class="${i === current ? "active" : ""}">${i}</button>`;
  }

  html += `<button onclick="loadPackets(${current + 1})" ${current === totalPages ? "disabled" : ""}>Next ›</button>`;
  html += `<button onclick="loadPackets(${totalPages})" ${current === totalPages ? "disabled" : ""}>Last »</button>`;
  html += `<span style="margin-left:12px;color:#8b949e;">Page ${current} of ${totalPages} (${formatNumber(total)} packets)</span>`;

  container.innerHTML = html;
}

// Show Packet Details Modal
async function showPacketDetails(id) {
  try {
    const res = await fetch(`/api/packets/${id}`);
    const packet = await res.json();

    document.getElementById("modalPacketNum").textContent = `#${packet.number}`;

    document.getElementById("modalBody").innerHTML = `
      <div class="detail-section">
        <h4>General Information</h4>
        <div class="detail-grid">
          <div class="detail-item">
            <label>Packet Number</label>
            <span>${packet.number}</span>
          </div>
          <div class="detail-item">
            <label>Time</label>
            <span>${packet.time || "N/A"}</span>
          </div>
          <div class="detail-item">
            <label>Length</label>
            <span>${packet.length} bytes</span>
          </div>
          <div class="detail-item">
            <label>Protocol</label>
            <span class="protocol-badge protocol-${packet.protocol}">${packet.protocol}</span>
          </div>
        </div>
      </div>
      
      <div class="detail-section">
        <h4>Addressing</h4>
        <div class="detail-grid">
          <div class="detail-item">
            <label>Source IP</label>
            <span>${packet.source || "N/A"}</span>
          </div>
          <div class="detail-item">
            <label>Destination IP</label>
            <span>${packet.destination || "N/A"}</span>
          </div>
          <div class="detail-item">
            <label>Source Port</label>
            <span>${packet.srcPort || "N/A"}</span>
          </div>
          <div class="detail-item">
            <label>Destination Port</label>
            <span>${packet.dstPort || "N/A"}</span>
          </div>
        </div>
      </div>
      
      <div class="detail-section">
        <h4>Layers</h4>
        <div class="detail-grid">
          ${packet.layers.map((l) => `<div class="detail-item"><span>${l}</span></div>`).join("")}
        </div>
      </div>
      
      ${
        packet.flags.length > 0
          ? `
        <div class="detail-section">
          <h4>TCP Flags</h4>
          <div class="detail-grid">
            ${packet.flags.map((f) => `<div class="detail-item"><span>${f}</span></div>`).join("")}
          </div>
        </div>
      `
          : ""
      }
      
      <div class="detail-section">
        <h4>Info</h4>
        <div class="detail-item" style="width:100%">
          <span>${packet.info || "N/A"}</span>
        </div>
      </div>
      
      <div class="detail-section">
        <h4>Raw Packet Data</h4>
        <div class="raw-data">${escapeHtml(packet.raw)}</div>
      </div>
    `;

    document.getElementById("packetModal").classList.add("active");
  } catch (error) {
    console.error("Error loading packet details:", error);
  }
}

function closeModal() {
  document.getElementById("packetModal").classList.remove("active");
}

// Close modal on outside click
document.getElementById("packetModal").addEventListener("click", (e) => {
  if (e.target.id === "packetModal") closeModal();
});

// Close modal on Escape key
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

// Load Protocols
async function loadProtocols() {
  try {
    const res = await fetch("/api/stats/protocols");
    const protocols = await res.json();

    const maxCount = protocols[0]?.count || 1;

    document.getElementById("protocolGrid").innerHTML = protocols
      .map(
        (p) => `
      <div class="protocol-card">
        <h4>
          <span class="protocol-badge protocol-${p.protocol}">${p.protocol}</span>
        </h4>
        <div class="stats">
          <span>${formatNumber(p.count)} packets</span>
          <span>${formatBytes(p.bytes)}</span>
          <span>${p.percentage}%</span>
        </div>
        <div class="protocol-bar">
          <div class="protocol-bar-fill" style="width: ${(p.count / maxCount) * 100}%"></div>
        </div>
      </div>
    `
      )
      .join("");
  } catch (error) {
    console.error("Error loading protocols:", error);
  }
}

// Load Conversations
async function loadConversations() {
  try {
    const res = await fetch("/api/conversations");
    conversationsData = await res.json();

    document.getElementById("conversationTableBody").innerHTML = conversationsData
      .map((c, index) => {
        const preview = c.dataSnippets.length > 0
          ? c.dataSnippets[0].info || `${c.dataSnippets[0].srcPort} → ${c.dataSnippets[0].dstPort}`
          : "No data";

        return `
          <tr>
            <td style="font-family: monospace;">${c.endpoints}</td>
            <td>${formatNumber(c.packets)}</td>
            <td>${formatBytes(c.bytes)}</td>
            <td>${c.protocols.map((p) => `<span class="protocol-badge protocol-${p}">${p}</span>`).join(" ")}</td>
            <td>
              <div class="data-preview" title="${escapeHtml(preview)}">${escapeHtml(truncate(preview, 30))}</div>
              <button class="btn-view-data" onclick="showConversationData(${index})">
                View All (${c.dataSnippets.length})
              </button>
            </td>
          </tr>
        `;
      })
      .join("");
  } catch (error) {
    console.error("Error loading conversations:", error);
  }
}

// Show Conversation Data Modal
function showConversationData(index) {
  const conv = conversationsData[index];
  if (!conv) return;

  document.getElementById("convEndpoints").textContent = conv.endpoints;

  // Summary
  document.getElementById("convSummary").innerHTML = `
    <div class="conv-summary-item">
      <div class="value">${formatNumber(conv.packets)}</div>
      <div class="label">Packets</div>
    </div>
    <div class="conv-summary-item">
      <div class="value">${formatBytes(conv.bytes)}</div>
      <div class="label">Total Data</div>
    </div>
    <div class="conv-summary-item">
      <div class="value">${conv.protocols.length}</div>
      <div class="label">Protocols</div>
    </div>
    <div class="conv-summary-item">
      <div class="value">${conv.protocols.join(", ")}</div>
      <div class="label">Protocol Types</div>
    </div>
  `;

  // Parse endpoints for direction coloring
  const [ep1, ep2] = conv.endpoints.split(" ↔ ").map((e) => e.trim());

  // Data table
  document.getElementById("convDataBody").innerHTML = conv.dataSnippets
    .map((d) => {
      const isOutbound = d.src === ep1;
      const dirClass = isOutbound ? "direction-out" : "direction-in";
      const dirArrow = isOutbound ? "→" : "←";

      return `
        <tr onclick="showPacketDetails(${d.num})" style="cursor: pointer;">
          <td>${d.num}</td>
          <td>${d.time || "-"}</td>
          <td class="${dirClass}">${d.src}${d.srcPort ? ":" + d.srcPort : ""}</td>
          <td class="${dirClass}">${d.dst}${d.dstPort ? ":" + d.dstPort : ""}</td>
          <td><span class="protocol-badge protocol-${d.protocol}">${d.protocol}</span></td>
          <td>${d.length}</td>
          <td>${escapeHtml(truncate(d.info || "-", 50))}</td>
        </tr>
      `;
    })
    .join("");

  document.getElementById("conversationModal").classList.add("active");
}

// Close Conversation Modal
function closeConvModal() {
  document.getElementById("conversationModal").classList.remove("active");
}

// Update the modal close handlers at the bottom
document.getElementById("conversationModal")?.addEventListener("click", (e) => {
  if (e.target.id === "conversationModal") closeConvModal();
});

// Update the escape key handler
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeModal();
    closeConvModal();
  }
});

// Load Timeline
async function loadTimeline() {
  try {
    const res = await fetch("/api/stats/timeline");
    const timeline = await res.json();

    const ctx = document.getElementById("timelineChart").getContext("2d");

    // Sample if too many points
    let data = timeline;
    if (timeline.length > 200) {
      const step = Math.ceil(timeline.length / 200);
      data = timeline.filter((_, i) => i % step === 0);
    }

    if (charts.timeline) charts.timeline.destroy();

    charts.timeline = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.map((t) => t.time),
        datasets: [
          {
            label: "Packets",
            data: data.map((t) => t.count),
            borderColor: "#58a6ff",
            backgroundColor: "rgba(88, 166, 255, 0.1)",
            fill: true,
            tension: 0.3,
            pointRadius: 0,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { labels: { color: "#e6edf3" } },
        },
        scales: {
          x: {
            ticks: { color: "#8b949e", maxTicksLimit: 15 },
            grid: { color: "#21262d" },
          },
          y: {
            ticks: { color: "#8b949e" },
            grid: { color: "#21262d" },
          },
        },
      },
    });
  } catch (error) {
    console.error("Error loading timeline:", error);
  }
}

// Utility Functions
function formatNumber(num) {
  return num.toLocaleString();
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function truncate(str, len) {
  if (!str) return "-";
  return str.length > len ? str.substring(0, len) + "..." : str;
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}