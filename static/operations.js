"use strict";
let activityChart;

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

byId("apply-live").addEventListener("click", () => {
    state.liveFilters = {minutes: byId("live-window").value, source: byId("live-source").value,
                         threat: byId("live-threat").value};
    state.liveResetPending = true;
    state.liveGeneration = (state.liveGeneration || 0) + 1;
    loadLive(true);
});
byId("refresh-incidents").addEventListener("click", loadIncidents);
setInterval(() => { if (state.view === "incidents" && !byId("session-dialog").open) loadIncidents(); }, 10000);
