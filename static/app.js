const DETECTION_SOURCES = [
  { id: "ML-*",      name: "ML model classification",       category: "model"    },
  { id: "META-1001", name: "Sustained packet-rate anomaly",  category: "metadata" },
  { id: "META-1002", name: "Encrypted service metadata",     category: "metadata" },
  { id: "META-0000", name: "Metadata baseline",              category: "baseline" },
  { id: "RESPONSE",  name: "Manual blocklist response",      category: "response" },
];

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const NOTIFICATION_PREF_KEY     = "ids-alert-popups";
const NOTIFIED_ALERTS_KEY       = "ids-alert-history";
const ALERT_NOTIFICATION_DELAY_MS   = 1200;
const ALERT_NOTIFICATION_DISPLAY_MS = 9000;

const state = {
  logs: [],
  metrics: { packets: 0, alerts: 0, encrypted: 0, blocked: 0 },
  filters: { search: "", severity: "all", action: "all" },
  view: "overview",
  health: null,
  alertPreference:    loadAlertPreference(),
  notifiedAlerts:     loadNotifiedAlerts(),
  pendingNotifications: [],
  notificationTimer:  null,
  capturePending:     null,
  // FIX (stop button): debounce flag + health poll interval reference
  _stopInFlight:    false,
  _healthInterval:  null,
};

const elements = {
  apiStatus:        document.querySelector("#api-status"),
  captureStatus:    document.querySelector("#capture-status"),
  modelStatus:      document.querySelector("#model-status"),
  deviceStatus:     document.querySelector("#device-status"),
  socketStatus:     document.querySelector("#socket-status"),
  alertPrefBadge:   document.querySelector("#alert-pref-badge"),
  alertPrefNote:    document.querySelector("#alert-pref-note"),
  enableAlerts:     document.querySelector("#enable-alerts"),
  muteAlerts:       document.querySelector("#mute-alerts"),
  resetAlertMemory: document.querySelector("#reset-alert-memory"),
  interfaceInput:   document.querySelector("#interface-input"),
  interfaceOptions: document.querySelector("#interface-options"),
  filterInput:      document.querySelector("#filter-input"),
  startCapture:     document.querySelector("#start-capture"),
  stopCapture:      document.querySelector("#stop-capture"),
  manualIp:         document.querySelector("#manual-ip"),
  manualBlock:      document.querySelector("#manual-block"),
  blocklist:        document.querySelector("#blocklist"),
  blockModeBadge:   document.querySelector("#block-mode-badge"),
  useMemoryMode:    document.querySelector("#use-memory-mode"),
  useFirewallMode:  document.querySelector("#use-firewall-mode"),
  warningSummary:   document.querySelector("#warning-summary"),
  pcapInput:        document.querySelector("#pcap-input"),
  analyzePcap:      document.querySelector("#analyze-pcap"),
  pcapResult:       document.querySelector("#pcap-result"),
  exportLogs:       document.querySelector("#export-logs"),
  clearLogs:        document.querySelector("#clear-logs"),
  exportResult:     document.querySelector("#export-result"),
  logTable:         document.querySelector("#log-table"),
  details:          document.querySelector("#event-details"),
  selectedSeverity: document.querySelector("#selected-severity"),
  deviceDetails:    document.querySelector("#device-details"),
  modelContract:    document.querySelector("#model-contract"),
  metricPackets:    document.querySelector("#metric-packets"),
  metricAlerts:     document.querySelector("#metric-alerts"),
  metricEncrypted:  document.querySelector("#metric-encrypted"),
  metricBlocked:    document.querySelector("#metric-blocked"),
  metricCritical:   document.querySelector("#metric-critical"),
  metricTopTalker:  document.querySelector("#metric-top-talker"),
  alertQueue:       document.querySelector("#alert-queue"),
  alertTimeline:    document.querySelector("#alert-timeline"),
  timelineTotal:    document.querySelector("#timeline-total"),
  topSources:       document.querySelector("#top-sources"),
  topTargets:       document.querySelector("#top-targets"),
  entityTotal:      document.querySelector("#entity-total"),
  trafficMix:       document.querySelector("#traffic-mix"),
  mixTotal:         document.querySelector("#mix-total"),
  ruleSummary:      document.querySelector("#rule-summary"),
  ruleList:         document.querySelector("#rule-list"),
  modelType:        document.querySelector("#model-type"),
  modelHealth:      document.querySelector("#model-health"),
  searchInput:      document.querySelector("#search-input"),
  severityFilter:   document.querySelector("#severity-filter"),
  actionFilter:     document.querySelector("#action-filter"),
  viewTabs:         document.querySelectorAll("[data-view-target]"),
  viewSections:     document.querySelectorAll("[data-view]"),
  logCount:         document.querySelector("#log-count"),
  chartTraffic:     document.querySelector("#chartTraffic"),
  chartAttacks:     document.querySelector("#chartAttacks"),
  chartPorts:       document.querySelector("#chartPorts"),
  chartSourceIPs:   document.querySelector("#chartSourceIPs"),
  chartProtocols:   document.querySelector("#chartProtocols"),
  toastTray:        document.querySelector("#toast-tray"),
};

const charts = { traffic: null, attacks: null, ports: null, sources: null, protocols: null };

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function setPill(element, text, className) {
  element.textContent = text;
  const baseClass = element.classList.contains("status-pill") ? "status-pill" : "pill";
  element.className = `${baseClass} ${className}`;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `Request failed: ${response.status}`);
  return payload;
}

// ---------------------------------------------------------------------------
// Capture controls
// ---------------------------------------------------------------------------

function renderCaptureControls() {
  const pending = state.capturePending;
  const running = Boolean(state.health?.capture?.running);

  // FIX (stop button): also lock out both buttons while _stopInFlight
  elements.startCapture.disabled = pending !== null || running || state._stopInFlight;
  elements.stopCapture.disabled  = pending !== null || !running || state._stopInFlight;

  if (pending === "start") { setPill(elements.captureStatus, "Starting capture", "warn"); return; }
  if (pending === "stop")  { setPill(elements.captureStatus, "Stopping capture",  "warn"); }
}

// ---------------------------------------------------------------------------
// Health / status
// ---------------------------------------------------------------------------

async function refreshHealth() {
  try {
    const health = await requestJson("/health");
    setPill(elements.apiStatus, "API online", "ok");
    setPill(
      elements.captureStatus,
      health.capture.running ? "Capture running" : "Capture stopped",
      health.capture.running ? "ok" : "neutral",
    );
    setPill(
      elements.modelStatus,
      health.model_loaded ? "Model loaded" : "Metadata mode",
      health.model_loaded ? "ok" : "warn",
    );

    renderBlocklist(health.capture.blocked_entries || []);
    renderBlockMode(health.capture.block_mode || "memory");
    renderWarningSummary(health.capture.warning_counts || {});
    renderModelContract(health);
    renderDevice(health.device);
    state.health = health;

    // FIX (counter accumulation): health.metrics contains DB totals (all-time).
    // We deliberately do NOT spread it into state.metrics.
    // state.metrics is managed locally and driven by session_packets from status.
    if (typeof health.capture.session_packets === "number") {
      state.metrics.packets = health.capture.session_packets;
    }

    renderAll();
    renderCaptureControls();
  } catch (error) {
    setPill(elements.apiStatus, "API offline", "danger");
    elements.modelContract.textContent = error.message;
    renderCaptureControls();
  }
}

// ---------------------------------------------------------------------------
// Alert preferences & notifications
// ---------------------------------------------------------------------------

function loadAlertPreference() {
  try { return window.localStorage.getItem(NOTIFICATION_PREF_KEY) || "unset"; } catch { return "unset"; }
}

function saveAlertPreference(value) {
  state.alertPreference = value;
  try { window.localStorage.setItem(NOTIFICATION_PREF_KEY, value); } catch {}
  renderAlertPreference();
}

function loadNotifiedAlerts() {
  try {
    const raw = window.sessionStorage.getItem(NOTIFIED_ALERTS_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(parsed) ? parsed : []);
  } catch { return new Set(); }
}

function persistNotifiedAlerts() {
  try { window.sessionStorage.setItem(NOTIFIED_ALERTS_KEY, JSON.stringify([...state.notifiedAlerts])); } catch {}
}

function resetNotifiedAlerts() {
  state.notifiedAlerts = new Set();
  persistNotifiedAlerts();
}

function renderAlertPreference() {
  const preference = state.alertPreference;
  elements.enableAlerts.disabled = preference === "enabled";
  elements.muteAlerts.disabled   = preference === "muted";
  if (preference === "enabled") {
    elements.alertPrefBadge.textContent = "Pop-ups on";
    elements.alertPrefNote.textContent  = "New attacks appear once per source IP and attack type.";
    return;
  }
  if (preference === "muted") {
    elements.alertPrefBadge.textContent = "Pop-ups muted";
    elements.alertPrefNote.textContent  = "Live alerts are still logged below, but pop-ups are muted.";
    return;
  }
  elements.alertPrefBadge.textContent = "Awaiting choice";
  elements.alertPrefNote.textContent  = "Choose whether the dashboard should show alert pop-ups.";
}

// ---------------------------------------------------------------------------
// Render helpers
// ---------------------------------------------------------------------------

function renderModelContract(health) {
  if (!health.model_loaded) {
    elements.modelContract.textContent =
      "No trained pipeline was found. The console is running metadata rules and response workflows.";
    return;
  }
  const count = health.expected_features ? health.expected_features.length : 0;
  elements.modelContract.textContent = `${count} expected model features from ${health.model_path}`;
}

function renderDevice(device) {
  if (!device) return;
  setPill(elements.deviceStatus, device.hostname || "Sensor online", "ok");
  replaceDefinitionList(elements.deviceDetails, [
    ["Device ID", device.device_id],
    ["Hostname",  device.hostname],
    ["Platform",  device.platform],
  ]);
}

function renderBlockMode(mode) {
  const m = String(mode || "memory").toLowerCase();
  elements.blockModeBadge.textContent    = m === "windows_firewall" ? "FIREWALL" : "MEMORY";
  elements.useMemoryMode.disabled        = m === "memory";
  elements.useFirewallMode.disabled      = m === "windows_firewall";
}

function renderWarningSummary(warningCounts) {
  const entries = Object.entries(warningCounts || {});
  if (!entries.length) { elements.warningSummary.textContent = "Recon warnings are clear."; return; }
  const summary = entries.sort((a, b) => b[1] - a[1]).slice(0, 3)
    .map(([ip, count]) => `${ip} (${count}/3)`).join(", ");
  elements.warningSummary.textContent = `Recon watchlist: ${summary}`;
}

function renderBlocklist(blockedEntries) {
  elements.blocklist.replaceChildren();
  if (!blockedEntries.length) {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.className = "muted";
    label.textContent = "No blocked IPs";
    item.append(label);
    elements.blocklist.append(item);
    return;
  }
  for (const entry of blockedEntries) {
    const item   = document.createElement("li");
    const stack  = document.createElement("div");
    const label  = document.createElement("strong");
    const meta   = document.createElement("span");
    const button = document.createElement("button");
    stack.className  = "blocklist-copy";
    label.textContent = entry.ip;
    meta.className    = "muted";
    meta.textContent  = entry.reason || "Blocked";
    button.textContent = "Unblock";
    button.addEventListener("click", () => unblockIp(entry.ip));
    stack.append(label, meta);
    item.append(stack, button);
    elements.blocklist.append(item);
  }
}

function addLog(log) {
  state.logs.unshift(log);
  state.logs = state.logs.slice(0, 300);
  state.metrics.packets += 1;
  if (log.encrypted_likely)    state.metrics.encrypted += 1;
  if (log.action === "blocked") state.metrics.blocked  += 1;
  if (isThreat(log))            state.metrics.alerts   += 1;
  renderAll();
}

function renderAll() {
  renderMetrics();
  renderRuleSummary();
  renderAlertPreference();
  renderAlertQueue();
  renderAlertTimeline();
  renderTopEntities();
  renderTrafficMix();
  renderModelHealth();
  renderCharts();
  renderLogs();
  renderView();
}

function renderMetrics() {
  const enriched    = state.logs.map(enrichLog);
  const criticalCount = enriched.filter((l) => l.severity === "critical").length;
  const topTalker   = topValue(state.logs.map((l) => l.source_ip).filter(Boolean));
  elements.metricPackets.textContent   = state.metrics.packets;
  elements.metricAlerts.textContent    = state.metrics.alerts;
  elements.metricEncrypted.textContent = state.metrics.encrypted;
  elements.metricBlocked.textContent   = state.metrics.blocked;
  elements.metricCritical.textContent  = criticalCount;
  elements.metricTopTalker.textContent = topTalker || "-";
}

function renderRuleSummary() {
  elements.ruleSummary.replaceChildren(
    ...[ ["Sources", DETECTION_SOURCES.length], ["Backend", "owned"],
         ["ML-backed", DETECTION_SOURCES.filter((s) => s.category === "model").length] ]
      .map(([label, value]) => {
        const item = document.createElement("div");
        const v = document.createElement("strong"); v.textContent = value;
        const l = document.createElement("span");   l.textContent = label;
        item.append(v, l); return item;
      }),
  );
  elements.ruleList.replaceChildren(
    ...DETECTION_SOURCES.map((source) => {
      const item  = document.createElement("article");
      const title = document.createElement("strong"); title.textContent = source.id;
      const meta  = document.createElement("span");   meta.textContent  = `${source.name} / ${source.category}`;
      item.append(title, meta); return item;
    }),
  );
}

function renderAlertQueue() {
  const alerts = deduplicatedAlerts(
    state.logs.map(enrichLog).filter((l) => isThreat(l) || isWarning(l) || l.action === "blocked")
  ).sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.count - a.count).slice(0, 8);

  elements.alertQueue.replaceChildren();
  if (!alerts.length) {
    const empty = document.createElement("p");
    empty.className = "muted empty-state";
    empty.textContent = "No active alerts in the current window.";
    elements.alertQueue.append(empty);
    return;
  }
  for (const alert of alerts) {
    const item  = document.createElement("button");
    const title = document.createElement("strong");
    const meta  = document.createElement("span");
    item.className    = "alert-card";
    title.textContent = alert.signature;
    meta.textContent  = `${alert.severity.toUpperCase()} / ${alert.count}x / ${formatEndpoint(
      alert.source_ip, alert.source_port
    )} -> ${formatEndpoint(alert.destination_ip, alert.destination_port)}`;
    item.append(title, meta);
    item.addEventListener("click", () => renderDetails(alert, "alerts"));
    elements.alertQueue.append(item);
  }
}

function alertIdentity(log) {
  const enriched = enrichLog(log);
  const label = attackLabel(enriched);
  if ((!isThreat(enriched) && !isWarning(enriched)) || label === "-") return null;
  return `${(enriched.source_ip || "unknown").toLowerCase()}|${String(label).toLowerCase()}`;
}

function maybeNotifyAlert(log) {
  if (state.alertPreference !== "enabled") return;
  const key = alertIdentity(log);
  if (!key || state.notifiedAlerts.has(key)) return;
  state.notifiedAlerts.add(key);
  persistNotifiedAlerts();
  const enriched = enrichLog(log);
  const isWarningEvent = isWarning(enriched);
  queueToast({
    title:    `${isWarningEvent ? "Warning" : "Attack"} from ${enriched.source_ip || "unknown source"}`,
    message:  `${attackLabel(enriched)} / ${isWarningEvent ? "WARNING" : enriched.severity.toUpperCase()} / ${formatEndpoint(enriched.destination_ip, enriched.destination_port)}`,
    severity: enriched.severity,
  });
}

function renderAlertTimeline() {
  const alerts  = state.logs.map(enrichLog).filter(isThreat);
  const buckets = countBy(alerts, (l) => {
    const d = new Date(l.timestamp);
    if (Number.isNaN(d.getTime())) return "unknown";
    d.setSeconds(0, 0);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  });
  const entries = Object.entries(buckets).slice(-10);
  elements.timelineTotal.textContent = `${alerts.length} alerts`;
  elements.alertTimeline.replaceChildren();
  if (!entries.length) { elements.alertTimeline.append(emptyState("No alert timeline yet.")); return; }
  const maxCount = Math.max(...entries.map(([, c]) => c), 1);
  for (const [label, count] of entries) {
    const row   = document.createElement("div");
    const time  = document.createElement("span");
    const track = document.createElement("div");
    const fill  = document.createElement("i");
    const value = document.createElement("strong");
    time.textContent  = label;
    fill.style.width  = `${Math.max((count / maxCount) * 100, 5)}%`;
    value.textContent = count;
    track.append(fill);
    row.append(time, track, value);
    elements.alertTimeline.append(row);
  }
}

function renderTopEntities() {
  const sources = state.logs.map((l) => l.source_ip).filter(Boolean);
  const targets = state.logs.map((l) => l.destination_ip).filter(Boolean);
  renderRankList(elements.topSources, sources);
  renderRankList(elements.topTargets, targets);
  elements.entityTotal.textContent = `${new Set([...sources, ...targets]).size} entities`;
}

function renderRankList(container, values) {
  const entries = Object.entries(countBy(values, (v) => v)).sort((a, b) => b[1] - a[1]).slice(0, 6);
  container.replaceChildren();
  if (!entries.length) { container.append(emptyState("No entities observed.")); return; }
  for (const [label, count] of entries) {
    const row   = document.createElement("div");
    const name  = document.createElement("span"); name.textContent  = label;
    const value = document.createElement("strong"); value.textContent = count;
    row.append(name, value);
    container.append(row);
  }
}

function renderTrafficMix() {
  const protocols = countBy(state.logs, (l) => l.protocol || "UNKNOWN");
  const entries   = Object.entries(protocols).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const total     = state.logs.length || 0;
  elements.mixTotal.textContent = `${total} events`;
  elements.trafficMix.replaceChildren();
  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "muted empty-state";
    empty.textContent = "Traffic mix appears after live events arrive.";
    elements.trafficMix.append(empty);
    return;
  }
  for (const [protocol, count] of entries) {
    const row   = document.createElement("div");
    const label = document.createElement("span"); label.textContent = protocol;
    const track = document.createElement("div");
    const fill  = document.createElement("i");
    const value = document.createElement("strong"); value.textContent = `${count}`;
    const pct   = total ? Math.round((count / total) * 100) : 0;
    fill.style.width = `${Math.max(pct, 4)}%`;
    track.append(fill);
    row.append(label, track, value);
    elements.trafficMix.append(row);
  }
}

function renderModelHealth() {
  if (!elements.modelHealth) return;
  const health    = state.health;
  const modelInfo = health?.model_info;
  elements.modelType.textContent = modelInfo?.type || (health?.model_loaded ? "loaded" : "metadata mode");
  if (!health?.model_loaded || !modelInfo) {
    elements.modelHealth.replaceChildren(emptyState("No ML model is loaded."));
    return;
  }
  const rows = [
    ["Model type",      modelInfo.type],
    ["Binary model",    modelInfo.binary_model_path || modelInfo.model_path],
    ["Attack model",    modelInfo.attack_model_path],
    ["Binary gate",     modelInfo.binary_threshold ? `${modelInfo.binary_threshold}%` : "-"],
    ["Decision gate",   modelInfo.attack_threshold ? confidenceBand(modelInfo.attack_threshold) : "-"],
    ["Feature columns", modelInfo.expected_features ? modelInfo.expected_features.length : 0],
    ["Flow gate",       `${health.capture.ml_min_packets} packets / ${health.capture.ml_min_duration}s`],
    ["Active flows",    health.capture.flow_count],
  ];
  const list = document.createElement("dl");
  list.className = "details model-details";
  replaceDefinitionList(list, rows);
  const featureBox = document.createElement("div");
  featureBox.className = "feature-cloud";
  for (const feature of modelInfo.expected_features || []) {
    const tag = document.createElement("span"); tag.textContent = feature;
    featureBox.append(tag);
  }
  elements.modelHealth.replaceChildren(list, featureBox);
}

function renderLogs() {
  elements.logTable.replaceChildren();
  if (elements.logCount) elements.logCount.textContent = `${filteredLogs().length} entries`;
  for (const log of filteredLogs().slice(0, 140)) {
    const enriched = enrichLog(log);
    const row = document.createElement("tr");
    row.classList.add(`severity-${enriched.severity}`);
    if (log.action === "blocked") row.classList.add("blocked-row");
    if (isThreat(log))            row.classList.add("alert-row");
    appendCell(row, formatTime(log.timestamp), "mono");
    appendCell(row, formatEndpoint(log.source_ip, log.source_port));
    appendCell(row, log.destination_port || "-", "mono");
    appendTagCell(row, verdictLabel(enriched), verdictClass(enriched));
    appendCell(row, attackLabel(enriched));
    appendTagCell(row, enriched.severity, enriched.severity);
    const actionCell    = document.createElement("td");
    const inspectButton = document.createElement("button");
    inspectButton.className   = "detail-link";
    inspectButton.textContent = "Inspect";
    inspectButton.addEventListener("click", () => renderDetails(enriched, "alerts"));
    actionCell.append(inspectButton);
    row.append(actionCell);
    row.addEventListener("dblclick", () => renderDetails(enriched, "alerts"));
    elements.logTable.append(row);
  }
}

function filteredLogs() {
  return state.logs.filter((log) => {
    const enriched = enrichLog(log);
    const haystack = [log.source_ip, log.destination_ip, log.protocol, log.prediction,
                      log.reason, enriched.signature, enriched.rule_id]
      .filter(Boolean).join(" ").toLowerCase();
    if (state.filters.search   && !haystack.includes(state.filters.search))       return false;
    if (state.filters.severity !== "all" && enriched.severity !== state.filters.severity) return false;
    if (state.filters.action   !== "all" && log.action        !== state.filters.action)   return false;
    return true;
  });
}

function appendCell(row, value, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = value ?? "-";
  row.append(cell);
}

function appendTagCell(row, value, className = "") {
  const cell = document.createElement("td");
  const tag  = document.createElement("span");
  tag.className   = `tag ${className}`;
  tag.textContent = value ?? "-";
  cell.append(tag);
  row.append(cell);
}

function renderDetails(log, view = null) {
  const enriched = enrichLog(log);
  if (view) setView(view);
  elements.selectedSeverity.textContent = enriched.severity;
  elements.selectedSeverity.className   = `tag ${enriched.severity}`;
  const rows = [
    ["Event ID",       log.id],
    ["Time",           formatDateTime(log.timestamp)],
    ["Signature",      enriched.signature],
    ["Rule ID",        enriched.rule_id],
    ["Severity",       enriched.severity],
    ["Source",         formatEndpoint(log.source_ip, log.source_port)],
    ["Destination",    formatEndpoint(log.destination_ip, log.destination_port)],
    ["Protocol",       log.protocol],
    ["Flow ID",        log.flow_id],
    ["Flow packets",   log.flow_packet_count],
    ["Flow bytes",     log.flow_byte_count],
    ["Flow duration",  formatSeconds(log.flow_duration)],
    ["Length",         log.length],
    ["Time diff",      log.time_diff],
    ["Packet rate",    log.packet_rate],
    ["Average size",   log.avg_length],
    ["Encrypted",      log.encrypted_likely ? "Likely" : "No"],
    ["Prediction",     log.prediction],
    ["Model certainty",confidenceBand(log.ml_confidence)],
    ["Binary label",   log.binary_label],
    ["Attack label",   log.attack_label],
    ["Action",         log.action],
    ["Reason",         log.reason],
    ["Response",       log.response_note],
  ];
  replaceDefinitionList(elements.details, rows);
  if (log.source_ip) {
    const dt = document.createElement("dt"); dt.textContent = "Response";
    const dd = document.createElement("dd");
    const button = document.createElement("button");
    button.textContent = "Block source IP";
    button.className   = "danger";
    button.addEventListener("click", () => blockIp(log.source_ip, `Blocked from event ${log.id}`));
    dd.append(button);
    elements.details.append(dt, dd);
  }
}

function verdictLabel(log) {
  if (log.action === "blocked") return "BLOCKED";
  if (isWarning(log))           return "WARNING";
  if (isThreat(log))            return "MALICIOUS";
  return "SAFE";
}

function verdictClass(log) {
  if (log.action === "blocked") return "critical";
  if (isWarning(log))           return "warning";
  return isThreat(log) ? "mal" : "safe";
}

function attackLabel(log) {
  if (!isThreat(log) && !isWarning(log)) return "-";
  return log.attack_label || log.prediction || log.signature || "-";
}

function replaceDefinitionList(list, rows) {
  list.replaceChildren(
    ...rows.flatMap(([key, value]) => {
      const dt = document.createElement("dt"); dt.textContent = key;
      const dd = document.createElement("dd"); dd.textContent = value ?? "-";
      return [dt, dd];
    }),
  );
}

function enrichLog(log) {
  const severity = normalizeSeverity(log.severity || fallbackSeverity(log));
  return {
    ...log,
    severity,
    rule_id:   log.rule_id   || "LEGACY-0000",
    signature: log.signature || log.prediction || "Metadata baseline",
  };
}

function deduplicatedAlerts(alerts) {
  const groups = new Map();
  for (const alert of alerts) {
    const key     = [alert.signature, alert.source_ip, alert.destination_ip, alert.severity].join("|");
    const current = groups.get(key);
    if (!current) { groups.set(key, { ...alert, count: 1 }); continue; }
    current.count += 1;
    if (Number(new Date(alert.timestamp)) > Number(new Date(current.timestamp)))
      Object.assign(current, alert, { count: current.count });
  }
  return [...groups.values()];
}

function isWarning(log) {
  const reason = String(log.reason || "").toLowerCase();
  return log.action === "warning" || reason === "model_uncertain_attack";
}

function isThreat(log) {
  if (log.action === "blocked") return true;
  if (isWarning(log))           return false;
  return normalizeSeverity(log.severity || fallbackSeverity(log)) !== "info";
}

function normalizeSeverity(value) {
  const normalized = String(value || "info").toLowerCase();
  return Object.hasOwn(SEVERITY_RANK, normalized) ? normalized : "info";
}

function fallbackSeverity(log) {
  const prediction = String(log.prediction || "").toLowerCase();
  if (["normal", "benign"].includes(prediction)) return "info";
  if (log.reason === "high_packet_rate")          return "critical";
  return "medium";
}

function countBy(items, getKey) {
  return items.reduce((counts, item) => {
    const key = getKey(item); counts[key] = (counts[key] || 0) + 1; return counts;
  }, {});
}

function topValue(values) {
  const counts = countBy(values, (v) => v);
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0];
}

function formatEndpoint(ip, port) { return ip ? (port ? `${ip}:${port}` : ip) : "-"; }
function formatTime(v)     { try { return new Date(v).toLocaleTimeString(); } catch { return v; } }
function formatDateTime(v) { try { return new Date(v).toLocaleString();     } catch { return v; } }

function confidenceBand(value) {
  if (value === null || value === undefined || value === "") return "-";
  const n = Number(value);
  if (Number.isNaN(n)) return value;
  if (n >= 90) return "Very high";
  if (n >= 80) return "High";
  if (n >= 65) return "Moderate";
  return "Low";
}

// ---------------------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------------------

function showToast({ title, message, severity = "medium" }) {
  if (!elements.toastTray) return;
  const toast   = document.createElement("article");
  const heading = document.createElement("strong"); heading.textContent = title;
  const detail  = document.createElement("p");      detail.textContent  = message;
  const dismiss = document.createElement("button");
  toast.className    = `toast ${normalizeSeverity(severity)}`;
  dismiss.className  = "toast-close";
  dismiss.type       = "button";
  dismiss.textContent = "Dismiss";
  dismiss.addEventListener("click", () => toast.remove());
  toast.append(heading, detail, dismiss);
  elements.toastTray.append(toast);
  window.setTimeout(() => toast.classList.add("visible"), 10);
  window.setTimeout(() => {
    toast.classList.remove("visible");
    window.setTimeout(() => toast.remove(), 220);
  }, ALERT_NOTIFICATION_DISPLAY_MS);
}

function queueToast(notification) {
  state.pendingNotifications.push(notification);
  flushToastQueue();
}

function flushToastQueue() {
  if (state.notificationTimer !== null || !state.pendingNotifications.length) return;
  const next = state.pendingNotifications.shift();
  showToast(next);
  state.notificationTimer = window.setTimeout(() => {
    state.notificationTimer = null;
    flushToastQueue();
  }, ALERT_NOTIFICATION_DISPLAY_MS + ALERT_NOTIFICATION_DELAY_MS);
}

// ---------------------------------------------------------------------------
// Charts
// ---------------------------------------------------------------------------

function initCharts() {
  if (!window.Chart) return;
  Chart.defaults.font.family = "'Inter', 'Segoe UI', sans-serif";
  Chart.defaults.color       = "#94a3b8";
  Chart.defaults.borderColor = "rgba(255,255,255,0.05)";

  if (elements.chartTraffic && !charts.traffic) {
    charts.traffic = new Chart(elements.chartTraffic, {
      type: "line",
      data: { labels: [], datasets: [
        { label: "Safe",   data: [], borderColor: "#22d3ee", backgroundColor: "rgba(34,211,238,0.08)",  fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 },
        { label: "Threat", data: [], borderColor: "#fb7185", backgroundColor: "rgba(251,113,133,0.08)", fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 },
      ]},
      options: chartOptions(),
    });
  }
  if (elements.chartAttacks && !charts.attacks) {
    charts.attacks = new Chart(elements.chartAttacks, {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: ["#fb7185","#fbbf24","#6366f1","#a78bfa","#22d3ee"], borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: "68%", plugins: { legend: { position: "bottom", labels: { usePointStyle: true, pointStyleWidth: 8 } } } },
    });
  }
  if (elements.chartPorts && !charts.ports) {
    charts.ports = new Chart(elements.chartPorts, {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#38bdf8", borderRadius: 6 }] },
      options: barOptions(),
    });
  }
  if (elements.chartSourceIPs && !charts.sources) {
    charts.sources = new Chart(elements.chartSourceIPs, {
      type: "bar",
      data: { labels: [], datasets: [{ data: [], backgroundColor: "#22d3ee", borderRadius: 4 }] },
      options: { ...barOptions(), indexAxis: "y" },
    });
  }
  if (elements.chartProtocols && !charts.protocols) {
    charts.protocols = new Chart(elements.chartProtocols, {
      type: "pie",
      data: { labels: [], datasets: [{ data: [], backgroundColor: ["#22d3ee","#6366f1","#fbbf24","#fb7185"], borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { usePointStyle: true, pointStyleWidth: 8 } } } },
    });
  }
}

function renderCharts() {
  if (!window.Chart) return;
  initCharts();
  const logs    = state.logs.map(enrichLog);
  const buckets = timeBuckets(logs, 12);
  updateChart(charts.traffic, buckets.labels, [buckets.safe, buckets.threat]);
  const attacks = Object.entries(countBy(logs.filter(isThreat), attackLabel)).sort((a, b) => b[1] - a[1]).slice(0, 6);
  updateChart(charts.attacks, attacks.map(([l]) => l), [attacks.map(([, c]) => c)]);
  const ports = Object.entries(countBy(logs.map((l) => l.destination_port || "Other"), (v) => String(v))).sort((a, b) => b[1] - a[1]).slice(0, 7);
  updateChart(charts.ports, ports.map(([l]) => l), [ports.map(([, c]) => c)]);
  const sources = Object.entries(countBy(logs.map((l) => l.source_ip || "-"), (v) => v)).sort((a, b) => b[1] - a[1]).slice(0, 6);
  updateChart(charts.sources, sources.map(([l]) => l), [sources.map(([, c]) => c)]);
  const protocols = Object.entries(countBy(logs, (l) => l.protocol || "Other")).sort((a, b) => b[1] - a[1]).slice(0, 5);
  updateChart(charts.protocols, protocols.map(([l]) => l), [protocols.map(([, c]) => c)]);
}

function updateChart(chart, labels, datasets) {
  if (!chart) return;
  chart.data.labels = labels;
  datasets.forEach((data, i) => { if (chart.data.datasets[i]) chart.data.datasets[i].data = data; });
  chart.update();
}

function timeBuckets(logs, count) {
  const buckets = [];
  const now = new Date();
  for (let i = count - 1; i >= 0; i--) {
    const d = new Date(now); d.setMinutes(now.getMinutes() - i * 5, 0, 0);
    buckets.push({ date: d, safe: 0, threat: 0 });
  }
  for (const log of logs) {
    const d = new Date(log.timestamp);
    if (Number.isNaN(d.getTime())) continue;
    const bucket = buckets.reduce((c, b) => Math.abs(b.date - d) < Math.abs(c.date - d) ? b : c, buckets[0]);
    if (isThreat(log)) bucket.threat++; else bucket.safe++;
  }
  return {
    labels: buckets.map((b) => b.date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })),
    safe:   buckets.map((b) => b.safe),
    threat: buckets.map((b) => b.threat),
  };
}

function chartOptions() {
  return {
    responsive: true, maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: { legend: { position: "top", labels: { usePointStyle: true, pointStyleWidth: 8 } } },
    scales: { y: { beginAtZero: true, grid: { color: "rgba(255,255,255,0.04)" } }, x: { grid: { display: false } } },
  };
}

function barOptions() {
  return {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: { y: { beginAtZero: true, grid: { color: "rgba(255,255,255,0.04)" } }, x: { grid: { display: false } } },
  };
}

function formatSeconds(value) {
  const n = Number(value);
  return Number.isNaN(n) ? (value ?? "-") : `${n.toFixed(2)}s`;
}

function emptyState(text) {
  const empty = document.createElement("p");
  empty.className = "muted empty-state";
  empty.textContent = text;
  return empty;
}

function setView(view) { state.view = view; renderView(); }

function renderView() {
  for (const tab of elements.viewTabs)
    tab.classList.toggle("active", tab.dataset.viewTarget === state.view);
  for (const section of elements.viewSections) {
    const views = section.dataset.view.split(" ");
    section.hidden = !views.includes(state.view);
  }
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

async function startCapture() {
  const payload = {
    interface:     elements.interfaceInput.value.trim() || null,
    packet_filter: elements.filterInput.value.trim()    || null,
  };

  // FIX (counter accumulation): reset frontend state before new session
  // so old-run logs and counts are wiped on both sides simultaneously.
  state.logs = [];
  state.metrics = { packets: 0, alerts: 0, encrypted: 0, blocked: 0 };
  renderAll();

  state.capturePending = "start";
  renderCaptureControls();
  try {
    await requestJson("/capture/start", { method: "POST", body: JSON.stringify(payload) });
    await refreshHealth();
  } finally {
    state.capturePending = null;
    renderCaptureControls();
  }
}

async function loadInterfaces() {
  try {
    const result = await requestJson("/capture/interfaces");
    elements.interfaceOptions.replaceChildren(
      ...result.interfaces.map((name) => {
        const opt = document.createElement("option"); opt.value = name; return opt;
      }),
    );
  } catch (error) { elements.socketStatus.textContent = error.message; }
}

async function stopCapture() {
  // FIX (stop button): full debounce — ignore all clicks while in-flight
  if (state._stopInFlight) return;
  state._stopInFlight  = true;
  state.capturePending = "stop";
  renderCaptureControls();

  // Pause health poll so it cannot race with stop and re-enable the button
  if (state._healthInterval) {
    clearInterval(state._healthInterval);
    state._healthInterval = null;
  }

  try {
    // Backend blocks until AsyncSniffer thread exits before responding,
    // so by the time we get a response is_running is guaranteed False.
    const status = await requestJson("/capture/stop", { method: "POST" });

    // Sync button state from the authoritative server response directly —
    // don't rely on refreshHealth() which could still race.
    state.health = { ...state.health, capture: status };
    renderCaptureControls();

    await refreshHealth();
  } catch (error) {
    console.error("Stop failed:", error);
    showToast({ title: "Stop failed", message: error.message, severity: "high" });
  } finally {
    state._stopInFlight  = false;
    state.capturePending = null;
    // Always restart health poll
    state._healthInterval = window.setInterval(refreshHealth, 5000);
    renderCaptureControls();
  }
}

// ---------------------------------------------------------------------------
// Blocklist / response / export
// ---------------------------------------------------------------------------

async function blockIp(ip, reason = "Manual block from IDS dashboard") {
  await requestJson("/blocklist", { method: "POST", body: JSON.stringify({ ip, reason }) });
  await refreshHealth();
}

async function unblockIp(ip) {
  await requestJson(`/blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" });
  await refreshHealth();
}

async function setBlockMode(mode) {
  await requestJson("/response/mode", { method: "POST", body: JSON.stringify({ mode }) });
  await refreshHealth();
}

async function exportLogs() {
  const result = await requestJson("/logs/export", { method: "POST" });
  elements.exportResult.textContent = `Exported to ${result.path}`;
  showToast({ title: "Logs exported", message: result.path, severity: "low" });
}

async function clearLogs() {
  await requestJson("/logs", { method: "DELETE" });
  state.logs    = [];
  state.metrics = { packets: 0, alerts: 0, encrypted: 0, blocked: 0 };
  resetNotifiedAlerts();
  elements.exportResult.textContent = "Stored logs cleared";
  renderAll();
  await refreshHealth();
  showToast({ title: "Stored logs cleared", message: "Dashboard history and unique alert memory were reset.", severity: "low" });
}

async function analyzePcap() {
  const file = elements.pcapInput.files[0];
  if (!file) { elements.pcapResult.textContent = "Choose a PCAP file first."; return; }

  const formData = new FormData();
  formData.append("file", file);
  elements.analyzePcap.disabled   = true;
  elements.pcapResult.textContent = "Analyzing capture…";

  // FIX (counter spike): reset frontend state before PCAP replay
  state.logs    = [];
  state.metrics = { packets: 0, alerts: 0, encrypted: 0, blocked: 0 };
  renderAll();

  try {
    const response = await fetch("/pcap/analyze", { method: "POST", body: formData });
    const result   = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.detail || `Upload failed: ${response.status}`);
    elements.pcapResult.textContent =
      `${result.processed_packets} packets analyzed / ${result.alert_count} alerts added`;
    await loadLogs();
    await refreshHealth();
  } finally {
    elements.analyzePcap.disabled = false;
  }
}

async function loadLogs() {
  // Default /logs returns session-only logs (current run)
  const result = await requestJson("/logs?limit=300");
  state.logs = result.logs.reverse();
  // Sync session counter from server's authoritative status
  if (result.session && typeof result.session.session_packets === "number") {
    state.metrics.packets = result.session.session_packets;
  }
  renderAll();
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------

function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket   = new WebSocket(`${protocol}://${window.location.host}/ws/logs`);

  socket.addEventListener("open", () => {
    elements.socketStatus.textContent = "Live stream connected";
  });

  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);

    if (message.type === "snapshot") {
      // FIX (counter accumulation): self.logs is session-only on the backend,
      // so this snapshot is empty between runs. Replace state cleanly.
      const snap = message.data.reverse();
      state.logs = snap;
      state.metrics.alerts    = snap.filter(isThreat).length;
      state.metrics.encrypted = snap.filter((l) => l.encrypted_likely).length;
      state.metrics.blocked   = snap.filter((l) => l.action === "blocked").length;
      // Don't set packets from snap.length — session_status event sets real count
      renderAll();
    }

    if (message.type === "session_status") {
      // FIX: sync session packet counter from server on connect/reconnect
      const s = message.data;
      if (typeof s.session_packets === "number") {
        state.metrics.packets   = s.session_packets;
        state.metrics.alerts    = state.logs.filter(isThreat).length;
        state.metrics.encrypted = state.logs.filter((l) => l.encrypted_likely).length;
        state.metrics.blocked   = state.logs.filter((l) => l.action === "blocked").length;
      }
      renderMetrics();
    }

    if (message.type === "packet_log") {
      addLog(message.data);
      maybeNotifyAlert(message.data);
      if (message.data.action === "warning" || message.data.action === "blocked") {
        refreshHealth();
      }
    }

    // FIX: smooth incremental PCAP progress updates
    if (message.type === "pcap_progress") {
      const p = message.data;
      elements.pcapResult.textContent =
        `Analyzing… ${p.processed} / ${p.limit} packets (${p.alerts} alerts so far)`;
    }

    if (message.type === "blocklist") refreshHealth();
  });

  socket.addEventListener("close", () => {
    elements.socketStatus.textContent = "Live stream reconnecting…";
    window.setTimeout(connectWebSocket, 1500);
  });
}

// ---------------------------------------------------------------------------
// Event listeners
// ---------------------------------------------------------------------------

elements.enableAlerts.addEventListener("click", () => {
  saveAlertPreference("enabled");
  showToast({ title: "Pop-up alerts enabled", message: "You will see one alert per source IP and attack type.", severity: "low" });
});
elements.muteAlerts.addEventListener("click", () => {
  saveAlertPreference("muted");
  showToast({ title: "Pop-up alerts muted", message: "Alerts continue in the feed without extra pop-ups.", severity: "low" });
});
elements.resetAlertMemory.addEventListener("click", () => {
  resetNotifiedAlerts();
  showToast({ title: "Alert memory reset", message: "Repeated attack types can notify again from the same IP.", severity: "low" });
});
elements.startCapture.addEventListener("click", () => startCapture().catch(alert));
elements.stopCapture.addEventListener("click",  () => stopCapture());
elements.manualBlock.addEventListener("click",  () => {
  const ip = elements.manualIp.value.trim();
  if (ip) blockIp(ip).catch(alert);
});
elements.useMemoryMode.addEventListener("click",   () => setBlockMode("memory").catch(alert));
elements.useFirewallMode.addEventListener("click",  () => setBlockMode("windows_firewall").catch(alert));
elements.exportLogs.addEventListener("click", () => exportLogs().catch(alert));
elements.clearLogs.addEventListener("click", () => {
  const confirmed = window.confirm("Clear all stored packet logs? This keeps model files and settings.");
  if (confirmed) clearLogs().catch(alert);
});
elements.analyzePcap.addEventListener("click", () =>
  analyzePcap().catch((error) => { elements.pcapResult.textContent = error.message; })
);
elements.searchInput.addEventListener("input", (event) => {
  state.filters.search = event.target.value.trim().toLowerCase();
  renderLogs();
});
elements.severityFilter.addEventListener("change", (event) => {
  state.filters.severity = event.target.value;
  renderLogs();
});
elements.actionFilter.addEventListener("change", (event) => {
  state.filters.action = event.target.value;
  renderLogs();
});
for (const tab of elements.viewTabs) {
  tab.addEventListener("click", () => setView(tab.dataset.viewTarget));
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

renderRuleSummary();
initCharts();
renderAll();
renderCaptureControls();
loadInterfaces();
refreshHealth();
connectWebSocket();
// FIX: store interval reference so stopCapture() can pause it
state._healthInterval = window.setInterval(refreshHealth, 5000);
