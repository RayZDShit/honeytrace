"use strict";

const state = {
    view: "live", sessionPage: 1, sessionTotal: 0, perPage: 50,
    liveEventCursor: 0, liveSessionCursor: 0, liveInitialized: false,
    livePaused: false, liveLoading: false,
};
const byId = id => document.getElementById(id);
const fmt = value => new Intl.NumberFormat().format(Number(value || 0));
const percent = value => `${(Number(value || 0) * 100).toFixed(1)}%`;
const displayName = value => String(value || "unknown").replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase());
const when = value => value ? new Date(value).toLocaleString() : "—";

async function api(path) {
    const response = await fetch(path, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { window.location.assign("/login"); throw new Error("Sign in required"); }
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    return response.json();
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function addCell(row, value, className = "") {
    const cell = document.createElement("td");
    cell.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
    if (className) cell.className = className;
    row.appendChild(cell);
    return cell;
}
function tag(value) {
    const span = document.createElement("span");
    span.className = "tag";
    span.textContent = value || "unknown";
    return span;
}
function setStatus(message, failed = false) {
    const node = byId("update-status");
    node.textContent = message;
    node.style.color = failed ? "var(--red)" : "";
}

function populateSelect(id, values, emptyLabel) {
    const select = byId(id);
    const selected = select.value;
    clear(select);
    const empty = document.createElement("option");
    empty.value = "";
    empty.textContent = emptyLabel;
    select.append(empty);
    values.forEach(value => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = id === "filter-source" ? value : displayName(value);
        select.append(option);
    });
    if ([...select.options].some(option => option.value === selected)) select.value = selected;
}

async function loadFilterOptions() {
    try {
        const [overview, sources] = await Promise.all([api("/api/overview"), api("/api/sources")]);
        populateSelect("filter-label", overview.labels.map(item => item.label), "All categories");
        populateSelect("filter-source", sources.map(item => item.source_name), "All sensors");
    } catch (error) {
        setStatus(`Filter options unavailable: ${error.message}`, true);
    }
}

function renderStats(target, stats) {
    const node = byId(target); clear(node);
    stats.forEach(item => {
        const card = document.createElement("article"); card.className = "stat";
        const label = document.createElement("div"); label.className = "stat-label"; label.textContent = item.label;
        const value = document.createElement("div"); value.className = "stat-value"; value.textContent = item.value;
        card.append(label, value);
        if (item.context) { const context = document.createElement("div"); context.className = "stat-context"; context.textContent = item.context; card.append(context); }
        node.append(card);
    });
}

function renderBars(target, rows, labelKey, valueKey, limit = 12, valueFormatter = fmt) {
    const node = byId(target); clear(node);
    const selected = [...rows].sort((a, b) => Number(b[valueKey]) - Number(a[valueKey])).slice(0, limit);
    const maximum = Math.max(...selected.map(row => Number(row[valueKey])), 1);
    selected.forEach(row => {
        const line = document.createElement("div"); line.className = "bar-row";
        const label = document.createElement("div"); label.className = "bar-label"; label.textContent = row[labelKey]; label.title = row[labelKey];
        const track = document.createElement("div"); track.className = "bar-track";
        const fill = document.createElement("div"); fill.className = "bar-fill"; fill.style.width = `${Math.max(Number(row[valueKey]) / maximum * 100, 1)}%`;
        track.append(fill);
        const value = document.createElement("div"); value.className = "bar-value"; value.textContent = valueFormatter(row[valueKey]);
        line.append(label, track, value); node.append(line);
    });
}

function setLiveConnection(message, mode = "live") {
    byId("live-connection").textContent = message;
    byId("live-beacon").className = `live-beacon${mode === "live" ? "" : ` ${mode}`}`;
}

function trimFeed(node, maximum) {
    while (node.children.length > maximum) node.lastElementChild.remove();
}

function liveEventNode(event, fresh) {
    const item = document.createElement("div");
    item.className = `live-event${fresh ? " fresh" : ""}`;
    item.dataset.eventId = event.id;
    const time = document.createElement("div");
    time.className = "live-time";
    time.textContent = new Date(event.timestamp).toLocaleTimeString();
    const name = document.createElement("div");
    name.className = "event-name";
    name.textContent = event.event_id;
    const source = document.createElement("div");
    source.className = "event-source";
    source.textContent = `${event.src_ip || "Unknown"} · ${event.source_name}`;
    const summary = document.createElement("div");
    summary.className = "event-summary";
    summary.textContent = event.message || "Telemetry event received";
    summary.title = summary.textContent;
    item.append(time, name, source, summary);
    return item;
}

function liveDetectionNode(detection, fresh) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `detection-card${fresh ? " fresh" : ""}`;
    button.dataset.sessionId = detection.id;
    button.addEventListener("click", () => openSession(detection.id));
    const heading = document.createElement("strong");
    heading.textContent = displayName(detection.final_label);
    const threat = tag(displayName(detection.threat_level));
    threat.classList.add(`threat-${detection.threat_level}`);
    const metadata = document.createElement("span");
    metadata.className = "detection-meta";
    metadata.textContent = `${detection.src_ip} · ${detection.source_name} · ${fmt(detection.event_count)} events`;
    const confidence = document.createElement("span");
    confidence.className = "detection-confidence";
    confidence.textContent = detection.prediction_confidence == null
        ? "Rule classified"
        : `${percent(detection.prediction_confidence)} model confidence`;
    button.append(heading, threat, metadata, confidence);
    return button;
}

async function loadLive(reset = false) {
    if (state.livePaused) return;
    if (reset) {
        state.liveResetPending = true;
        state.liveGeneration = (state.liveGeneration || 0) + 1;
    }
    if (state.liveLoading) return;
    state.liveLoading = true;
    const generation = state.liveGeneration || 0;
    const initial = !state.liveInitialized || state.liveResetPending;
    state.liveResetPending = false;
    try {
        const params = new URLSearchParams({
            after_event_id: state.liveEventCursor, after_revision: state.liveRevision || 0,
            initial: String(initial), limit: 100,
            since: new Date(Date.now() - Number(state.liveFilters?.minutes || 5) * 60000).toISOString(),
            source: state.liveFilters?.source || "", threat: state.liveFilters?.threat || "",
        });
        const data = await api("/api/live?" + params);
        if (state.livePaused || generation !== (state.liveGeneration || 0)) return;
        if (initial || data.reset) {
            clear(byId("live-events")); clear(byId("live-detections"));
        }
        renderStats("live-stats", [
            { label: "Events / 5 min", value: fmt(data.stats.events_5m) },
            { label: "Sessions / 5 min", value: fmt(data.stats.detections_5m) },
            { label: "High risk / 5 min", value: fmt(data.stats.high_risk_5m) },
            { label: "Sources / 5 min", value: fmt(data.stats.sources_5m) },
        ]);
        const eventFeed = byId("live-events"), detectionFeed = byId("live-detections");
        if (data.events.length) eventFeed.querySelector(".live-empty")?.remove();
        data.events.forEach(event => {
            if (!eventFeed.querySelector('[data-event-id="' + event.id + '"]')) {
                const node = liveEventNode(event, !initial);
                node.dataset.timestamp = event.timestamp;
                eventFeed.prepend(node);
            }
        });
        if (data.detections.length) detectionFeed.querySelector(".live-empty")?.remove();
        data.detections.forEach(detection => {
            detectionFeed.querySelector('[data-session-id="' + detection.id + '"]')?.remove();
            if (!detection.hidden) {
                const node = liveDetectionNode(detection, !initial);
                node.dataset.timestamp = detection.last_seen;
                detectionFeed.prepend(node);
            }
        });
        const cutoff = Date.now() - Number(state.liveFilters?.minutes || 5) * 60000;
        [eventFeed, detectionFeed].forEach(feed => {
            feed.querySelectorAll("[data-timestamp]").forEach(node => {
                if (new Date(node.dataset.timestamp).getTime() < cutoff) node.remove();
            });
            if (!feed.children.length) {
                const empty = document.createElement("div");
                empty.className = "live-empty"; empty.textContent = "No activity in the selected window";
                feed.append(empty);
            }
        });
        trimFeed(eventFeed, 100); trimFeed(detectionFeed, 60);
        state.liveEventCursor = data.event_cursor; state.liveRevision = data.revision;
        state.liveInitialized = true;
        const online = data.sensors.filter(sensor => sensor.online);
        setLiveConnection(online.length ? "Sensor online - monitoring" : "Sensor offline - dashboard connected",
                          online.length ? "live" : "error");
        byId("live-updated").textContent = "Last sync " + new Date(data.generated_at).toLocaleTimeString()
            + (data.has_more ? " - catching up" : " - up to date");
        if (typeof renderOperations === "function") renderOperations(data);
        if (state.view === "live") setStatus("Live telemetry synchronized");
        if (data.has_more) setTimeout(() => { if (state.view === "live") loadLive(); }, 100);
    } catch (error) {
        if (initial) state.liveInitialized = false;
        setLiveConnection("Telemetry connection unavailable", "error");
        byId("live-updated").textContent = "Automatic retry enabled";
        if (state.view === "live") setStatus("Live monitor error: " + error.message, true);
    } finally {
        state.liveLoading = false;
        if (state.liveResetPending && !state.livePaused) loadLive();
    }
}

async function loadOverview() {
    try {
        const data = await api("/api/overview");
        renderStats("overview-stats", [
            { label: "Events", value: fmt(data.events) },
            { label: "Behavioral sessions", value: fmt(data.sessions) },
            { label: "Unique sources", value: fmt(data.unique_ips) },
            { label: "Sensors", value: fmt(data.sources) },
            { label: "High-risk sessions", value: fmt(data.high_risk), context: "High and critical" },
        ]);
        renderBars("label-chart", data.labels, "label", "count");
        renderBars("threat-chart", data.threats, "level", "count", 6);
        const body = byId("recent-events"); clear(body);
        data.recent.forEach(event => {
            const row = document.createElement("tr");
            addCell(row, when(event.timestamp)); addCell(row, event.source_name); addCell(row, event.src_ip);
            addCell(row, event.event_id); addCell(row, event.message);
            body.append(row);
        });
        setStatus(`Updated ${new Date().toLocaleTimeString()}`);
    } catch (error) { setStatus(`Dashboard error: ${error.message}`, true); }
}

function sessionQuery() {
    const params = new URLSearchParams({ page: state.sessionPage, per_page: state.perPage });
    [["label", "filter-label"], ["threat", "filter-threat"], ["source", "filter-source"], ["search", "filter-search"]]
        .forEach(([key, id]) => { const value = byId(id).value.trim(); if (value) params.set(key, value); });
    return params.toString();
}

async function loadSessions() {
    try {
        const data = await api(`/api/sessions?${sessionQuery()}`);
        state.sessionTotal = data.total;
        byId("session-total").textContent = `${fmt(data.total)} sessions`;
        const body = byId("session-rows"); clear(body);
        data.sessions.forEach(session => {
            const row = document.createElement("tr");
            addCell(row, when(session.first_seen)); addCell(row, session.source_name); addCell(row, session.src_ip);
            addCell(row, fmt(session.event_count)); addCell(row, fmt(session.login_failures)); addCell(row, fmt(session.command_count));
            const rule = document.createElement("td"); rule.append(tag(session.rule_label)); row.append(rule);
            addCell(row, session.predicted_label || "—");
            const final = document.createElement("td"); final.append(tag(session.final_label)); row.append(final);
            addCell(row, session.threat_level, `threat-${session.threat_level}`);
            const action = document.createElement("td"); const button = document.createElement("button");
            button.className = "detail-button"; button.textContent = "Inspect"; button.addEventListener("click", () => openSession(session.id));
            action.append(button); row.append(action); body.append(row);
        });
        const pages = Math.max(Math.ceil(data.total / state.perPage), 1);
        byId("page-info").textContent = `Page ${state.sessionPage} of ${pages}`;
        byId("previous-page").disabled = state.sessionPage <= 1;
        byId("next-page").disabled = state.sessionPage >= pages;
        setStatus(`Loaded ${data.sessions.length} sessions`);
    } catch (error) { setStatus(`Session error: ${error.message}`, true); }
}

function detailItem(label, value) {
    const item = document.createElement("div"); item.className = "detail-item";
    const small = document.createElement("small"); small.textContent = label;
    const content = document.createElement("div"); content.textContent = value ?? "—";
    item.append(small, content); return item;
}

async function openSession(id) {
    const dialog = byId("session-dialog"), content = byId("session-detail");
    clear(content); content.textContent = "Loading session…"; dialog.showModal();
    try {
        const data = await api(`/api/sessions/${id}`); clear(content);
        byId("dialog-title").textContent = `Session ${id}`;
        const grid = document.createElement("div"); grid.className = "detail-grid";
        [
            ["Sensor", data.session.source_name], ["Source", data.session.src_ip],
            ["Rule label", data.session.rule_label], ["Model prediction", data.session.predicted_label || "Not scored"],
            ["Confidence", data.session.prediction_confidence == null ? "—" : percent(data.session.prediction_confidence)],
            ["Final label", data.session.final_label], ["Threat", data.session.threat_level],
            ["Duration", `${Number(data.session.duration_seconds).toFixed(2)} s`],
        ].forEach(item => grid.append(detailItem(item[0], item[1])));
        content.append(grid);
        const reason = document.createElement("div"); reason.className = "reason"; reason.textContent = data.session.rule_reason; content.append(reason);
        const title = document.createElement("h2"); title.textContent = "Event timeline"; title.style.marginBottom = "14px"; content.append(title);
        const list = document.createElement("div"); list.className = "event-list";
        data.events.forEach(event => {
            const item = document.createElement("div"); item.className = "event";
            const time = document.createElement("div"); time.className = "event-time"; time.textContent = when(event.timestamp);
            const name = document.createElement("strong"); name.textContent = event.event_id;
            item.append(time, name);
            const summary = event.command || event.url || event.message || event.credential_preview;
            if (summary) { const code = document.createElement("code"); code.textContent = summary; item.append(code); }
            list.append(item);
        });
        content.append(list);
    } catch (error) { content.textContent = `Unable to load session: ${error.message}`; }
}

async function loadModel() {
    try {
        const data = await api("/api/model");
        byId("model-empty").hidden = data.available; byId("model-content").hidden = !data.available;
        if (!data.available) return;
        const metrics = data.metrics;
        renderStats("model-stats", [
            { label: "Balanced accuracy", value: percent(metrics.balanced_accuracy) },
            { label: "Macro F1", value: percent(metrics.macro_f1) },
            { label: "Weighted F1", value: percent(metrics.weighted_f1) },
            { label: "Training sessions", value: fmt(data.train_samples) },
            { label: "Holdout sessions", value: fmt(data.test_samples) },
        ]);
        byId("model-disclaimer").textContent = metrics.disclaimer;
        renderBars("feature-chart", Object.entries(data.feature_importance).map(([feature, importance]) => ({ feature, importance })), "feature", "importance", 14, percent);
        const reportBody = byId("classification-report"); clear(reportBody);
        metrics.labels.forEach(label => {
            const item = metrics.classification_report[label] || {}; const row = document.createElement("tr");
            addCell(row, label); addCell(row, percent(item.precision)); addCell(row, percent(item.recall)); addCell(row, percent(item["f1-score"])); addCell(row, fmt(item.support)); reportBody.append(row);
        });
        const holder = byId("confusion-matrix"); clear(holder); const table = document.createElement("table"); table.className = "matrix";
        const head = document.createElement("thead"), headRow = document.createElement("tr"); addCell(headRow, "Actual \\ Predicted");
        metrics.labels.forEach(label => { const th = document.createElement("th"); th.textContent = label; headRow.append(th); }); head.append(headRow); table.append(head);
        const body = document.createElement("tbody"); metrics.confusion_matrix.forEach((values, index) => {
            const row = document.createElement("tr"); const th = document.createElement("th"); th.textContent = metrics.labels[index]; row.append(th);
            values.forEach(value => addCell(row, fmt(value))); body.append(row);
        }); table.append(body); holder.append(table);
        setStatus(`Model ${data.model_version} · ${data.algorithm}`);
    } catch (error) { setStatus(`Model error: ${error.message}`, true); }
}

const loaders = { overview: loadOverview, live: () => loadLive(!state.liveInitialized), sessions: loadSessions, incidents: () => loadIncidents(), model: loadModel };
document.querySelectorAll(".nav-item").forEach(button => button.addEventListener("click", () => {
    state.view = button.dataset.view;
    document.querySelectorAll(".nav-item").forEach(item => item.classList.toggle("active", item === button));
    document.querySelectorAll(".view").forEach(view => view.classList.toggle("active", view.id === `view-${state.view}`));
    byId("page-title").textContent = button.textContent;
    loaders[state.view]();
}));
byId("apply-filters").addEventListener("click", () => { state.sessionPage = 1; loadSessions(); });
byId("toggle-live").addEventListener("click", () => {
    state.livePaused = !state.livePaused;
    state.liveGeneration = (state.liveGeneration || 0) + 1;
    byId("toggle-live").textContent = state.livePaused ? "Resume stream" : "Pause stream";
    if (state.livePaused) {
        setLiveConnection("Stream paused", "paused");
        byId("live-updated").textContent = "Updates are paused";
    } else {
        setLiveConnection("Reconnecting to telemetry");
        loadLive();
    }
});
byId("filter-search").addEventListener("keydown", event => {
    if (event.key === "Enter") { state.sessionPage = 1; loadSessions(); }
});
byId("previous-page").addEventListener("click", () => { if (state.sessionPage > 1) { state.sessionPage--; loadSessions(); } });
byId("next-page").addEventListener("click", () => { state.sessionPage++; loadSessions(); });
byId("close-dialog").addEventListener("click", () => byId("session-dialog").close());
byId("session-dialog").addEventListener("click", event => { if (event.target === byId("session-dialog")) byId("session-dialog").close(); });

loadFilterOptions();
loadLive(true);
setInterval(() => { if (state.view === "live" && !state.livePaused) loadLive(); }, 2000);
setInterval(() => { if (state.view === "overview") loadOverview(); }, 15000);
