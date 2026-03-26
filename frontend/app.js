/**
 * AI Secure Data Intelligence Platform — Frontend Logic
 * Handles: tab switching, drag-and-drop, API calls, results rendering
 */

const API_BASE = "http://localhost:8000";

// ── State ────────────────────────────────────────────────────────────────────
let currentTab = "text";
let currentLogFile = null;
let currentDocFile = null;
let allFindings = [];

// ── DOM References ────────────────────────────────────────────────────────────
const analyzeBtn = document.getElementById("analyzeBtn");
const analyzeBtnText = document.getElementById("analyzeBtnText");
const emptyState = document.getElementById("emptyState");
const loadingState = document.getElementById("loadingState");
const resultsContent = document.getElementById("resultsContent");

// ── Initialization ────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupDragAndDrop();
  setupFilePickers();
  setupAnalyzeButton();
  setupFindingsFilters();
});

// ── Tab Switching ─────────────────────────────────────────────────────────────
function setupTabs() {
  const tabs = document.querySelectorAll(".tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const tabName = tab.dataset.tab;
      currentTab = tabName;

      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      tab.classList.add("active");
      document.getElementById(`content-${tabName}`).classList.add("active");
    });
  });
}

// ── Drag & Drop (Log Files) ───────────────────────────────────────────────────
function setupDragAndDrop() {
  const dropZone = document.getElementById("logDropZone");
  if (!dropZone) return;

  ["dragenter", "dragover"].forEach(event => {
    dropZone.addEventListener(event, (e) => {
      e.preventDefault();
      dropZone.classList.add("dragover");
    });
  });
  ["dragleave", "drop"].forEach(event => {
    dropZone.addEventListener(event, () => dropZone.classList.remove("dragover"));
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) handleLogFile(file);
  });

  // Doc drop zone
  const docDropZone = document.getElementById("docDropZone");
  if (docDropZone) {
    ["dragenter", "dragover"].forEach(event => {
      docDropZone.addEventListener(event, (e) => { e.preventDefault(); docDropZone.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(event => {
      docDropZone.addEventListener(event, () => docDropZone.classList.remove("dragover"));
    });
    docDropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (file) handleDocFile(file);
    });
  }
}

function setupFilePickers() {
  const logInput = document.getElementById("logFileInput");
  if (logInput) logInput.addEventListener("change", (e) => { if (e.target.files[0]) handleLogFile(e.target.files[0]); });

  const docInput = document.getElementById("docFileInput");
  if (docInput) docInput.addEventListener("change", (e) => { if (e.target.files[0]) handleDocFile(e.target.files[0]); });

  const removeFile = document.getElementById("removeFile");
  if (removeFile) removeFile.addEventListener("click", () => { currentLogFile = null; showDropZone("log"); });

  const removeDoc = document.getElementById("removeDoc");
  if (removeDoc) removeDoc.addEventListener("click", () => { currentDocFile = null; showDropZone("doc"); });
}

function handleLogFile(file) {
  currentLogFile = file;
  document.getElementById("selectedFileName").textContent = file.name;

  const reader = new FileReader();
  reader.onload = (e) => {
    const preview = document.getElementById("filePreview");
    const lines = e.target.result.split("\n").slice(0, 8).join("\n");
    preview.textContent = lines + (e.target.result.split("\n").length > 8 ? "\n... (truncated)" : "");
  };
  reader.readAsText(file);

  document.getElementById("logDropZone").style.display = "none";
  document.getElementById("fileSelected").style.display = "flex";
}

function handleDocFile(file) {
  currentDocFile = file;
  document.getElementById("selectedDocName").textContent = file.name;
  document.getElementById("docDropZone").style.display = "none";
  document.getElementById("docSelected").style.display = "flex";
}

function showDropZone(type) {
  if (type === "log") {
    document.getElementById("logDropZone").style.display = "flex";
    document.getElementById("fileSelected").style.display = "none";
  } else {
    document.getElementById("docDropZone").style.display = "flex";
    document.getElementById("docSelected").style.display = "none";
  }
}

// ── Analyze Button ────────────────────────────────────────────────────────────
function setupAnalyzeButton() {
  analyzeBtn.addEventListener("click", runAnalysis);
}

async function runAnalysis() {
  const options = {
    mask: document.getElementById("optMask").checked,
    block_high_risk: document.getElementById("optBlock").checked,
    log_analysis: document.getElementById("optAI").checked,
  };

  let useFileUpload = false;
  let content = "";
  let inputType = currentTab;

  // Determine content based on active tab
  if (currentTab === "text") {
    content = document.getElementById("textInput").value.trim();
  } else if (currentTab === "log") {
    if (currentLogFile) {
      useFileUpload = true;
    } else {
      content = document.getElementById("textInput").value.trim();
    }
  } else if (currentTab === "file") {
    if (currentDocFile) {
      useFileUpload = true;
    }
  } else if (currentTab === "sql") {
    content = document.getElementById("sqlInput").value.trim();
  } else if (currentTab === "chat") {
    content = document.getElementById("chatInput").value.trim();
  }

  if (!useFileUpload && !content) {
    flashError("Please enter content or upload a file to analyze.");
    return;
  }

  showLoading();

  try {
    let data;
    if (useFileUpload) {
      data = await uploadFileForAnalysis(
        currentTab === "log" ? currentLogFile : currentDocFile,
        options
      );
    } else {
      data = await analyzeJSON({ input_type: inputType, content, options });
    }
    renderResults(data);
  } catch (err) {
    showError(err.message || "Analysis failed. Is the backend running?");
  }
}

async function analyzeJSON(payload) {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok && res.status !== 403) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Server error ${res.status}`);
  }
  return res.json();
}

async function uploadFileForAnalysis(file, options) {
  const form = new FormData();
  form.append("file", file);
  form.append("mask", options.mask);
  form.append("block_high_risk", options.block_high_risk);
  form.append("log_analysis", options.log_analysis);

  const res = await fetch(`${API_BASE}/analyze/upload`, {
    method: "POST",
    body: form,
  });
  if (!res.ok && res.status !== 403) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Server error ${res.status}`);
  }
  return res.json();
}

// ── Loading State ─────────────────────────────────────────────────────────────
function showLoading() {
  emptyState.style.display = "none";
  resultsContent.style.display = "none";
  loadingState.style.display = "flex";
  analyzeBtn.classList.add("loading");
  analyzeBtnText.textContent = "Analyzing...";

  // Animate steps
  const steps = ["step1", "step2", "step3", "step4"];
  steps.forEach(id => document.getElementById(id).classList.remove("active", "done"));
  document.getElementById("step1").classList.add("active");

  let step = 0;
  const interval = setInterval(() => {
    if (step < steps.length - 1) {
      document.getElementById(steps[step]).classList.remove("active");
      document.getElementById(steps[step]).classList.add("done");
      step++;
      document.getElementById(steps[step]).classList.add("active");
    } else {
      clearInterval(interval);
    }
  }, 600);
  window._loadingInterval = interval;
}

function stopLoading() {
  if (window._loadingInterval) clearInterval(window._loadingInterval);
  loadingState.style.display = "none";
  analyzeBtn.classList.remove("loading");
  analyzeBtnText.textContent = "Analyze Now";
}

// ── Render Results ────────────────────────────────────────────────────────────
function renderResults(data) {
  stopLoading();
  allFindings = data.findings || [];

  // Risk Dashboard
  renderRiskDashboard(data);

  // Blocked alert
  const blockedAlert = document.getElementById("blockedAlert");
  blockedAlert.style.display = data.blocked ? "block" : "none";

  // Summary
  document.getElementById("summaryText").textContent = data.summary || "No summary available.";
  const aiBadge = document.getElementById("aiBadge");
  aiBadge.style.display = data.ai_powered ? "inline-block" : "none";

  // Insights
  renderList("insightsList", data.insights || [], "insight-li");
  renderList("anomaliesList", data.anomalies || [], "anomaly-li");
  renderList("recommendationsList", data.recommendations || [], "rec-li");

  // Findings table
  renderFindingsTable(allFindings, "all");

  // Log viewer
  renderLogViewer(data.highlighted_lines || []);

  // Brute force toast
  if (data.stats && data.stats.brute_force_detected) {
    showBruteForceToast();
  }

  resultsContent.style.display = "flex";
}

function renderRiskDashboard(data) {
  const score = data.risk_score || 0;
  const level = data.risk_level || "safe";
  const counts = data.severity_counts || {};
  const stats = data.stats || {};

  // Animated score counter
  animateCounter("riskScoreNum", score);

  // Risk ring
  const ring = document.getElementById("riskRingFill");
  const circumference = 326.7;
  const pct = Math.min(score / 100, 1);
  ring.style.strokeDashoffset = circumference * (1 - pct);

  // Color the ring
  const colors = { safe: "#10b981", low: "#10b981", medium: "#f59e0b", high: "#f97316", critical: "#ef4444" };
  ring.style.stroke = colors[level] || "#00f5ff";

  // Risk level badge
  const badge = document.getElementById("riskLevelBadge");
  badge.textContent = level.toUpperCase();
  badge.className = `risk-level-badge badge-${level}`;

  // Meta details
  document.getElementById("totalFindings").textContent = (data.findings || []).length;
  document.getElementById("totalLines").textContent = stats.total_lines || 0;

  const actionEl = document.getElementById("actionTaken");
  actionEl.textContent = (data.action || "—").toUpperCase();
  actionEl.style.color = data.action === "blocked" ? "var(--red)" : data.action === "masked" ? "var(--yellow)" : "var(--green)";

  const aiEl = document.getElementById("aiPoweredBadge");
  aiEl.textContent = data.ai_powered ? "✨ ON" : "RULES";
  aiEl.style.color = data.ai_powered ? "var(--cyan)" : "var(--text-dim)";

  // Severity counts
  document.getElementById("sevCritical").textContent = counts.critical || 0;
  document.getElementById("sevHigh").textContent = counts.high || 0;
  document.getElementById("sevMedium").textContent = counts.medium || 0;
  document.getElementById("sevLow").textContent = counts.low || 0;

  // Score card border
  const card = document.getElementById("riskScoreCard");
  const borderColors = { safe: "rgba(16,185,129,0.3)", low: "rgba(16,185,129,0.3)", medium: "rgba(245,158,11,0.3)", high: "rgba(249,115,22,0.4)", critical: "rgba(239,68,68,0.5)" };
  card.style.filter = level === "critical" ? "drop-shadow(0 0 12px rgba(239,68,68,0.4))" : "none";
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  let current = 0;
  const step = Math.ceil(target / 20);
  const interval = setInterval(() => {
    current = Math.min(current + step, target);
    el.textContent = current;
    if (current >= target) clearInterval(interval);
  }, 40);
}

function renderList(listId, items, className) {
  const ul = document.getElementById(listId);
  if (!items || items.length === 0) {
    ul.innerHTML = `<li class="${className}"><span style="color:var(--text-dimmer)">None detected</span></li>`;
    return;
  }
  ul.innerHTML = items.map(item => `<li class="${className}">${escapeHtml(item)}</li>`).join("");
}

// ── Findings Table ────────────────────────────────────────────────────────────
function setupFindingsFilters() {
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      renderFindingsTable(allFindings, btn.dataset.filter);
    });
  });
}

function renderFindingsTable(findings, filter) {
  const tbody = document.getElementById("findingsBody");
  const noFindings = document.getElementById("noFindings");
  const countBadge = document.getElementById("findingsCountBadge");

  const filtered = filter === "all" ? findings : findings.filter(f => f.risk === filter);

  countBadge.textContent = filtered.length;

  if (filtered.length === 0) {
    tbody.innerHTML = "";
    noFindings.style.display = "block";
    return;
  }
  noFindings.style.display = "none";

  tbody.innerHTML = filtered.map((f, i) => `
    <tr>
      <td class="line-num">${i + 1}</td>
      <td><span class="type-pill">${escapeHtml(f.type || "—")}</span></td>
      <td><span class="risk-pill ${f.risk || "low"}">${(f.risk || "low").toUpperCase()}</span></td>
      <td class="line-num">${f.line != null ? f.line : "—"}</td>
      <td class="content-preview" title="${escapeHtml(f.line_content || "")}">${escapeHtml(truncate(f.line_content || f.value || "—", 60))}</td>
    </tr>
  `).join("");
}

// ── Log Viewer ────────────────────────────────────────────────────────────────
function renderLogViewer(lines) {
  const viewer = document.getElementById("logViewer");
  const card = document.getElementById("logViewerCard");

  if (!lines || lines.length === 0) {
    card.style.display = "none";
    return;
  }

  card.style.display = "block";
  viewer.innerHTML = lines.map(line => `
    <div class="log-line ${line.risk !== 'none' ? `risk-${line.risk}` : ''}">
      <span class="log-line-num">${line.line_number}</span>
      <span class="log-line-content">${escapeHtml(line.content || "")}</span>
    </div>
  `).join("");
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showBruteForceToast() {
  const toast = document.getElementById("bruteForceToast");
  toast.style.display = "block";
  setTimeout(() => { toast.style.display = "none"; }, 6000);
}

// ── Error States ──────────────────────────────────────────────────────────────
function showError(message) {
  stopLoading();
  emptyState.style.display = "flex";
  emptyState.innerHTML = `
    <div class="empty-icon">⚠️</div>
    <h3>Analysis Failed</h3>
    <p style="color:var(--red)">${escapeHtml(message)}</p>
    <p style="color:var(--text-dim);font-size:12px">Make sure the backend is running: <code style="color:var(--cyan)">uvicorn main:app --reload</code></p>
  `;
}

function showLoading() {
  emptyState.style.display = "none";
  resultsContent.style.display = "none";
  loadingState.style.display = "flex";
  analyzeBtn.classList.add("loading");
  analyzeBtnText.textContent = "Analyzing...";

  const steps = ["step1", "step2", "step3", "step4"];
  steps.forEach(id => document.getElementById(id).classList.remove("active", "done"));
  document.getElementById("step1").classList.add("active");

  let step = 0;
  if (window._loadingInterval) clearInterval(window._loadingInterval);
  window._loadingInterval = setInterval(() => {
    if (step < steps.length - 1) {
      document.getElementById(steps[step]).classList.remove("active");
      document.getElementById(steps[step]).classList.add("done");
      step++;
      document.getElementById(steps[step]).classList.add("active");
    } else {
      clearInterval(window._loadingInterval);
    }
  }, 700);
}

function flashError(msg) {
  const btn = analyzeBtn;
  const origText = analyzeBtnText.textContent;
  analyzeBtnText.textContent = "⚠ " + msg;
  btn.style.background = "linear-gradient(135deg, #ef4444, #b91c1c)";
  setTimeout(() => {
    analyzeBtnText.textContent = origText;
    btn.style.background = "";
  }, 2500);
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function truncate(str, maxLen) {
  if (!str) return "";
  return str.length > maxLen ? str.slice(0, maxLen) + "…" : str;
}
