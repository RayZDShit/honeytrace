"use strict";
let activityChart;
let alertCursor = 0;
let alertSoundMuted = localStorage.getItem("honeytrace-alert-sound") === "muted";
let alertToastTimer;

function textNode(tagName, value, className = "") {
    const node = document.createElement(tagName);
    node.textContent = value;
    node.className = className;
    return node;
}

function renderOperations(data) {
    const health = byId("sensor-health"); clear(health);
    if (!data.sensors.length) health.append(textNode("p", "No sensor heartbeat yet. Start the SSH sensor."));
    data.sensors.forEach(sensor => {
        const item = textNode("div", "", "sensor-row");
        item.append(textNode("strong", sensor.name + (sensor.online ? " / Online" : " / Offline"),
                    sensor.online ? "threat-low" : "threat-critical"));
        item.append(textNode("p", "SSH port " + sensor.port + " · " + sensor.active_connections
            + " connections · " + sensor.backlog + " queued · " + sensor.processing_ms + " ms last batch"));
        item.append(textNode("small", "Heartbeat: " + when(sensor.heartbeat)
            + " · Dropped events: " + sensor.dropped_events));
        if (sensor.error) item.append(textNode("p", sensor.error, "threat-critical"));
        health.append(item);
        const select = byId("live-source");
        if (![...select.options].some(option => option.value === sensor.name)) {
            const option = textNode("option", sensor.name); option.value = sensor.name; select.append(option);
        }
    });
    const active = byId("active-connections"); clear(active);
    if (!data.active_connections.length) active.append(textNode("span", "No active connections", "quiet"));
    data.active_connections.forEach(item => {
        active.append(textNode("div", item.src_ip + " · " + item.sensor + " · opened " + when(item.opened_at), "sensor-row"));
    });
    if (typeof Chart === "undefined") return;
    const buckets = new Map(data.timeline.map(point => [point.minute, point.count]));
    const now = new Date(data.generated_at);
    const points = Array.from({length: 15}, (_, index) => {
        const date = new Date(now.getTime() - (14 - index) * 60000);
        return {label: date.toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"}),
                count: buckets.get(date.toISOString().slice(0, 16)) || 0};
    });
    if (!activityChart) {
        activityChart = new Chart(byId("activity-chart"), {
            type: "line",
            data: {labels: [], datasets: [{label: "Events", data: [], borderColor: "#f5b942",
                backgroundColor: "rgba(245,185,66,.12)", fill: true, tension: .25, pointRadius: 0}]},
            options: {responsive: true, maintainAspectRatio: false, animation: false,
                plugins: {legend: {display: false}},
                scales: {x: {ticks: {color: "#9ea2aa", maxTicksLimit: 5}},
                         y: {beginAtZero: true, ticks: {precision: 0, color: "#9ea2aa"}}}}
        });
    }
    activityChart.data.labels = points.map(p => p.label);
    activityChart.data.datasets[0].data = points.map(p => p.count);
    activityChart.update("none");
}

async function loadIncidents() {
    try {
        const params = new URLSearchParams({status: byId("incident-status").value,
                                          severity: byId("incident-severity").value});
        const rows = await api("/api/incidents?" + params);
        const list = byId("incident-list"); clear(list);
        if (!rows.length) list.append(textNode("p", "No incidents match these filters.", "quiet"));
        rows.forEach(row => {
            const button = textNode("button", "", "incident-row");
            button.append(textNode("strong", "#" + row.id + " " + displayName(row.category)),
                textNode("span", row.status, "tag"), textNode("span", row.severity, "threat-" + row.severity),
                textNode("small", row.src_ip + " · " + row.sensor + " · " + fmt(row.event_count) + " events"),
                textNode("small", when(row.last_seen)));
            button.addEventListener("click", () => openIncident(row.id));
            list.append(button);
        });
        setStatus(rows.length + " incidents loaded");
    } catch (error) { setStatus(error.message, true); }
}

async function openIncident(id) {
    const dialog = byId("session-dialog"), holder = byId("session-detail");
    if (!dialog.open) dialog.showModal();
    clear(holder); holder.append(textNode("p", "Loading incident..."));
    try {
        const data = await api("/api/incidents/" + id), item = data.incident;
        clear(holder); byId("dialog-title").textContent = "Incident #" + id;
        holder.append(textNode("h2", displayName(item.category)),
            textNode("p", item.src_ip + " · " + item.sensor + " · " + item.severity),
            textNode("p", item.reason, "reason"));
        const actions = textNode("div", "", "incident-actions");
        const evidence = textNode("button", "Inspect session", "stream-toggle");
        evidence.addEventListener("click", () => { dialog.close(); openSession(item.session_id); });
        const download = textNode("a", "Download CSV evidence", "stream-toggle");
        download.href = "/api/incidents/" + id + "/export.csv";
        actions.append(evidence, download); holder.append(actions);
        const form = document.createElement("form"); form.className = "incident-form";
        const label = textNode("label", "Status"), status = document.createElement("select");
        ["New", "Investigating", "Resolved"].forEach(value => status.append(textNode("option", value)));
        status.value = item.status; label.append(status);
        const noteLabel = textNode("label", "Analyst note"), note = document.createElement("textarea");
        note.maxLength = 4000; note.rows = 4; noteLabel.append(note);
        const save = textNode("button", "Save investigation", "primary"); save.type = "submit";
        const errorText = textNode("p", "", "threat-critical"); errorText.setAttribute("role", "alert");
        form.append(label, noteLabel, save, errorText); holder.append(form);
        form.addEventListener("submit", async event => {
            event.preventDefault(); save.disabled = true;
            try {
                const response = await fetch("/api/incidents/" + id, {
                    method: "PATCH", headers: {"Content-Type": "application/json",
                        "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content},
                    body: JSON.stringify({status: status.value, note: note.value}),
                    signal: AbortSignal.timeout(15000),
                });
                if (!response.ok) throw new Error((await response.json()).error || "Save failed");
                await openIncident(id); loadIncidents();
            } catch (error) { errorText.textContent = error.message; save.disabled = false; }
        });
        holder.append(textNode("h2", "Investigation history"));
        data.notes.forEach(note => {
            const box = textNode("article", "", "sensor-row");
            box.append(textNode("small", note.author + " · " + when(note.created_at)), textNode("p", note.body));
            holder.append(box);
        });
    } catch (error) { clear(holder); holder.append(textNode("p", error.message)); }
}

function csrfHeaders() {
    return {"Content-Type": "application/json",
            "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content};
}

function playCriticalAlert() {
    if (alertSoundMuted) return;
    try {
        const context = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = context.createOscillator(), gain = context.createGain();
        oscillator.type = "sine"; oscillator.frequency.value = 760;
        gain.gain.setValueAtTime(.08, context.currentTime);
        gain.gain.exponentialRampToValueAtTime(.001, context.currentTime + .32);
        oscillator.connect(gain); gain.connect(context.destination);
        oscillator.start(); oscillator.stop(context.currentTime + .32);
        oscillator.addEventListener("ended", () => context.close());
    } catch (_) { /* Browser audio is optional and may be blocked by policy. */ }
}

function showAlertToast(alert) {
    const toast = byId("alert-toast");
    toast.className = "alert-toast alert-" + alert.severity;
    toast.textContent = `${alert.severity.toUpperCase()}: ${displayName(alert.category)} from ${alert.src_ip}`;
    toast.hidden = false;
    clearTimeout(alertToastTimer);
    alertToastTimer = setTimeout(() => { toast.hidden = true; }, 7000);
    if (alert.severity === "critical") playCriticalAlert();
}

async function setAlertAcknowledged(id, acknowledged) {
    const response = await fetch("/api/alerts/" + id, {
        method: "PATCH", headers: csrfHeaders(), body: JSON.stringify({acknowledged}),
        signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw new Error((await response.json()).error || "Unable to update alert");
    await loadAlerts();
}

function renderAlert(alert) {
    const item = textNode("article", "", "alert-item alert-" + alert.severity
        + (alert.acknowledged_at ? " acknowledged" : ""));
    const heading = textNode("div", "", "alert-item-heading");
    heading.append(textNode("strong", displayName(alert.category)),
                   textNode("span", alert.severity, "threat-" + alert.severity));
    const typeNames = {new: "New incident", escalated: "Escalated to critical", reopened: "Incident reopened"};
    item.append(heading,
        textNode("p", (typeNames[alert.alert_type] || "Security alert") + " · #" + alert.incident_id),
        textNode("small", alert.src_ip + " · " + alert.sensor + " · " + when(alert.created_at)));
    const delivery = alert.discord_status === "sent" ? "Discord sent"
        : alert.discord_status === "failed" ? "Discord delivery failed" : "Dashboard alert";
    item.append(textNode("small", delivery, "alert-delivery"));
    const actions = textNode("div", "", "alert-item-actions");
    const inspect = textNode("button", "Open incident", "stream-toggle");
    inspect.type = "button";
    inspect.addEventListener("click", async () => {
        if (!alert.acknowledged_at) await setAlertAcknowledged(alert.id, true);
        closeAlertDrawer(); openIncident(alert.incident_id);
    });
    const acknowledge = textNode("button", alert.acknowledged_at ? "Mark unread" : "Acknowledge", "stream-toggle");
    acknowledge.type = "button";
    acknowledge.addEventListener("click", () => setAlertAcknowledged(alert.id, !alert.acknowledged_at));
    actions.append(inspect, acknowledge); item.append(actions);
    return item;
}

async function loadAlerts(initial = false) {
    try {
        const data = await api("/api/alerts?limit=50");
        const list = byId("alert-list"); clear(list);
        if (!data.alerts.length) list.append(textNode("p", "No high or critical alerts yet.", "quiet"));
        data.alerts.forEach(alert => list.append(renderAlert(alert)));
        const badge = byId("alert-count");
        badge.textContent = data.unread > 99 ? "99+" : String(data.unread);
        badge.hidden = data.unread === 0;
        const maxId = data.alerts.reduce((maximum, alert) => Math.max(maximum, alert.id), 0);
        if (!initial && alertCursor) {
            const newest = data.alerts.filter(alert => alert.id > alertCursor).sort((a, b) => a.id - b.id);
            newest.forEach(showAlertToast);
        }
        alertCursor = Math.max(alertCursor, maxId);
    } catch (error) {
        if (!initial) setStatus("Alert refresh failed: " + error.message, true);
    }
}

async function loadDiscordSettings() {
    try {
        const data = await api("/api/settings/discord");
        byId("discord-alert-status").textContent = data.configured
            ? `Configured${data.updated_by ? " by " + data.updated_by : ""}`
            : "Not configured";
        byId("remove-discord-webhook").disabled = !data.configured;
    } catch (error) {
        byId("discord-setting-message").textContent = error.message;
    }
}

async function saveDiscordWebhook() {
    const input = byId("discord-webhook"), message = byId("discord-setting-message");
    const webhook = input.value.trim();
    if (!webhook) { message.textContent = "Enter the webhook URL first."; return; }
    message.textContent = "Saving…";
    try {
        const response = await fetch("/api/settings/discord", {
            method: "PUT", headers: csrfHeaders(), body: JSON.stringify({webhook}),
            signal: AbortSignal.timeout(15000),
        });
        if (!response.ok) throw new Error((await response.json()).error || "Unable to save webhook");
        input.value = "";
        message.textContent = "Webhook saved. New alerts will be sent with the complete source IP.";
        await loadDiscordSettings(); await loadAlerts();
    } catch (error) { message.textContent = error.message; }
}

async function removeDiscordWebhook() {
    const message = byId("discord-setting-message");
    message.textContent = "Removing…";
    try {
        const response = await fetch("/api/settings/discord", {
            method: "DELETE", headers: csrfHeaders(), signal: AbortSignal.timeout(15000),
        });
        if (!response.ok) throw new Error((await response.json()).error || "Unable to remove webhook");
        byId("discord-webhook").value = "";
        message.textContent = "Discord delivery disabled.";
        await loadDiscordSettings(); await loadAlerts();
    } catch (error) { message.textContent = error.message; }
}

function openAlertDrawer() {
    byId("alert-drawer").hidden = false; byId("alert-overlay").hidden = false;
    byId("alert-button").setAttribute("aria-expanded", "true");
    loadAlerts(); loadDiscordSettings();
}

function closeAlertDrawer() {
    byId("alert-drawer").hidden = true; byId("alert-overlay").hidden = true;
    byId("alert-button").setAttribute("aria-expanded", "false");
}

byId("apply-live").addEventListener("click", () => {
    state.liveFilters = {minutes: byId("live-window").value, source: byId("live-source").value,
                         threat: byId("live-threat").value};
    state.liveResetPending = true;
    state.liveGeneration = (state.liveGeneration || 0) + 1;
    loadLive(true);
});
byId("refresh-incidents").addEventListener("click", loadIncidents);
byId("alert-button").addEventListener("click", openAlertDrawer);
byId("close-alerts").addEventListener("click", closeAlertDrawer);
byId("alert-overlay").addEventListener("click", closeAlertDrawer);
byId("toggle-alert-sound").textContent = alertSoundMuted ? "Enable critical sound" : "Mute critical sound";
byId("toggle-alert-sound").addEventListener("click", () => {
    alertSoundMuted = !alertSoundMuted;
    localStorage.setItem("honeytrace-alert-sound", alertSoundMuted ? "muted" : "enabled");
    byId("toggle-alert-sound").textContent = alertSoundMuted ? "Enable critical sound" : "Mute critical sound";
});
byId("save-discord-webhook").addEventListener("click", saveDiscordWebhook);
byId("remove-discord-webhook").addEventListener("click", removeDiscordWebhook);
byId("acknowledge-alerts").addEventListener("click", async () => {
    const response = await fetch("/api/alerts/acknowledge-all", {
        method: "POST", headers: csrfHeaders(), signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) throw new Error((await response.json()).error || "Unable to acknowledge alerts");
    loadAlerts();
});
loadAlerts(true);
loadDiscordSettings();
setInterval(() => loadAlerts(), 5000);
setInterval(() => { if (state.view === "incidents" && !byId("session-dialog").open) loadIncidents(); }, 10000);
