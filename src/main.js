(() => {
  "use strict";

  const hasTauri = Boolean(window.__TAURI__ && window.__TAURI__.core);
  const invoke = hasTauri
    ? window.__TAURI__.core.invoke
    : async () => {
        throw new Error("Tauri API not available. Run this UI inside the LeakForce desktop app.");
      };
  const listen = hasTauri
    ? window.__TAURI__.event.listen
    : async () => () => {};

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => Array.from(document.querySelectorAll(selector));

  const state = {
    view: "dashboard",
    session: null,
    report: null,
    brute: null,
    settings: null,
    history: [],
    engines: null,
    appInfo: null,
    filter: "All",
    search: "",
    revealedSecrets: new Map(),
    scanning: false,
    bruteRunning: false,
    bruteTotal: 0,
    bruteAttempts: 0,
    checkingEngines: false,
  };

  const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
  const PAGE_META = {
    dashboard: {
      title: "Dashboard",
      sub: "Leak score, findings and scan overview",
    },
    sensitive: {
      title: "Sensitive Scan",
      sub: "Check exposed files, JavaScript secrets and common database ports",
    },
    brute: {
      title: "Brute Force",
      sub: "Authorized lab-only login testing",
    },
    history: {
      title: "History",
      sub: "Last 20 scans and login tests",
    },
    settings: {
      title: "Settings",
      sub: "Engine paths, scan defaults and component status",
    },
  };

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  function errMessage(error) {
    if (typeof error === "string") return error;
    if (error && typeof error.message === "string") return error.message;
    try {
      return JSON.stringify(error);
    } catch {
      return String(error);
    }
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function fmtDuration(ms) {
    if (typeof ms !== "number" || Number.isNaN(ms)) return "—";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    const seconds = ms / 1000;
    if (seconds < 60) return `${seconds.toFixed(1)} s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${Math.round(seconds % 60)}s`;
  }

  function fmtSeconds(seconds) {
    if (!Number.isFinite(seconds) || seconds < 0) return "—";
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
    return `${Math.floor(seconds / 86400)}d ${Math.floor((seconds % 86400) / 3600)}h`;
  }

  function fmtDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  }

  function scoreColor(score) {
    if (score >= 70) return "#f87171";
    if (score >= 40) return "#fbbf24";
    return "#34d399";
  }

  function scoreCaption(score) {
    if (score >= 70) return "High exposure";
    if (score >= 40) return "Moderate exposure";
    if (score > 0) return "Low exposure";
    return "No scoring findings";
  }

  function severityClass(severity) {
    const key = String(severity || "").toLowerCase();
    return SEVERITIES.map((item) => item.toLowerCase()).includes(key) ? `sev-${key}` : "sev-info";
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast("Copied to clipboard.", "success");
    } catch {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        toast("Copied to clipboard.", "success");
      } catch {
        toast("Could not copy. Select the text manually.", "error");
      }
      area.remove();
    }
  }

  function toast(message, kind = "info") {
    const box = $("#toasts");
    if (!box) return;
    const node = el(
      "div",
      `fade-in rounded-lg border px-4 py-3 text-sm shadow-xl toast-${kind}`
    );
    node.textContent = message;
    box.appendChild(node);
    window.setTimeout(() => {
      node.style.opacity = "0";
      node.style.transition = "opacity .25s";
      window.setTimeout(() => node.remove(), 250);
    }, 6000);
  }

  function addLog(level, message) {
    const log = $("#log");
    if (!log) return;
    const safeLevel = ["info", "success", "warning", "error", "debug"].includes(level)
      ? level
      : "info";
    const row = el("div", `fade-in log-${safeLevel}`);
    const time = new Date().toLocaleTimeString([], { hour12: false });
    const stamp = el("span", "text-slate-600 mr-2", time);
    const text = el("span", "", String(message ?? ""));
    row.appendChild(stamp);
    row.appendChild(text);
    log.appendChild(row);
    while (log.childElementCount > 500) log.firstElementChild.remove();
    log.parentElement.parentElement.scrollTop = 0;
    log.scrollTop = log.scrollHeight;
    const count = $("#log-count");
    if (count) count.textContent = String(log.childElementCount);
  }

  function setEngineIndicator(ok, label) {
    const dot = $("#engine-dot");
    const text = $("#engine-label");
    if (dot) {
      dot.className = "w-2 h-2 rounded-full " + (ok ? "dot-ok" : "dot-bad");
    }
    if (text) text.textContent = label;
  }

  // ---------------------------------------------------------------------
  // Navigation
  // ---------------------------------------------------------------------

  function switchView(name) {
    if (!PAGE_META[name]) return;
    state.view = name;
    $$("[data-nav]").forEach((button) => {
      button.classList.toggle("active", button.dataset.nav === name);
    });
    $$("[data-view-panel]").forEach((panel) => {
      panel.classList.toggle("hidden", panel.dataset.viewPanel !== name);
    });
    $("#page-title").textContent = PAGE_META[name].title;
    $("#page-sub").textContent = PAGE_META[name].sub;

    if (name === "history") refreshHistory();
    if (name === "settings") {
      renderEngineStatus();
      renderAppInfo();
    }
    if (name === "brute") prefillBruteTarget();
  }

  function prefillBruteTarget() {
    const input = $("#brute-target");
    if (!input || input.value.trim()) return;
    const target = state.report?.target || state.brute?.target;
    if (target) input.value = target;
  }

  // ---------------------------------------------------------------------
  // Session rendering
  // ---------------------------------------------------------------------

  async function refreshSession() {
    try {
      state.session = await invoke("get_session");
      renderSession();
    } catch (error) {
      addLog("error", `Could not load session: ${errMessage(error)}`);
    }
  }

  function renderSession() {
    const session = state.session || {};
    state.report = session.report || null;
    state.brute = session.brute || null;
    const score = session.score ?? 0;
    const breakdown = session.scoreBreakdown || [];
    const loginResult = session.loginResult || "Not tested";

    renderHeaderBadge();
    renderDashboard(score, breakdown, loginResult);
    renderScanSummary();
    renderFindings();
    renderFileChecks();
    renderBruteSummary();
    updateExportButtons();
    if (state.report?.target) {
      const scanInput = $("#scan-target");
      if (scanInput && !scanInput.value.trim()) scanInput.value = state.report.target;
      localStorage.setItem("leakforce.lastTarget", state.report.target);
    }
  }

  function renderHeaderBadge() {
    const badge = $("#target-badge");
    if (!badge) return;
    const target = state.report?.target || state.brute?.target || "";
    if (!target) {
      badge.classList.add("hidden");
      return;
    }
    badge.classList.remove("hidden");
    badge.textContent = target;
    badge.title = target;
  }

  function renderDashboard(score, breakdown, loginResult) {
    const arc = $("#score-arc");
    const circumference = 364.42;
    if (arc) {
      const clamped = Math.max(0, Math.min(100, Number(score) || 0));
      arc.style.strokeDashoffset = String(circumference * (1 - clamped / 100));
      arc.style.stroke = scoreColor(clamped);
    }
    const scoreValue = $("#score-value");
    if (scoreValue) scoreValue.textContent = String(score ?? 0);
    const caption = $("#score-caption");
    if (caption) {
      caption.textContent =
        state.report || state.brute ? scoreCaption(Number(score) || 0) : "No scan yet";
    }

    const report = state.report;
    $("#card-sensitive").textContent = report ? report.sensitiveFound : "0";
    $("#card-secrets").textContent = report ? report.secretsFound : "0";
    $("#card-login").textContent = report
      ? report.loginResult
      : state.brute
      ? loginResult
      : "Not tested";
    $("#card-time").textContent = report ? fmtDuration(report.durationMs) : "—";

    const empty = $("#dash-empty");
    const content = $("#dash-content");
    const hasData = Boolean(report || state.brute);
    empty.classList.toggle("hidden", hasData);
    content.classList.toggle("hidden", !hasData);

    const target = report?.target || state.brute?.target || "";
    $("#dash-target").textContent = target;
    $("#dash-started").textContent = report?.startedAt
      ? fmtDate(report.startedAt)
      : state.brute?.startedAt
      ? fmtDate(state.brute.startedAt)
      : "";

    const list = $("#score-breakdown");
    list.replaceChildren();
    if (!breakdown.length) {
      list.appendChild(el("li", "text-xs text-slate-500", "No score-contributing findings."));
    } else {
      breakdown.forEach((item) => {
        const row = el("li", "flex items-center justify-between gap-4");
        row.appendChild(el("span", "text-slate-300", item.label));
        row.appendChild(el("span", "font-mono text-emerald-300", `+${item.points}`));
        list.appendChild(row);
      });
      const raw = breakdown.reduce((sum, item) => sum + (Number(item.points) || 0), 0);
      if (raw > 100) {
        list.appendChild(
          el("li", "flex items-center justify-between gap-4 text-xs text-slate-500", "Capped at maximum")
        );
      }
    }

    renderDashboardFindings();
    updateExportButtons();
  }

  function renderDashboardFindings() {
    const container = $("#dash-findings");
    const empty = $("#dash-findings-empty");
    container.replaceChildren();
    const findings = state.report?.findings || [];
    const top = findings.slice(0, 6);
    if (!top.length) {
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");
    top.forEach((finding) => {
      const row = el("div", "rounded-lg border border-slate-800 bg-slate-900/40 p-2.5");
      const head = el("div", "flex items-center gap-2");
      const badge = el(
        "span",
        `badge ${severityClass(finding.severity)}`,
        finding.severity
      );
      head.appendChild(badge);
      head.appendChild(el("span", "text-xs font-semibold truncate", finding.title));
      row.appendChild(head);
      const location = finding.url || finding.file || "";
      if (location) {
        row.appendChild(el("div", "text-[10px] text-slate-500 mt-1 truncate", location));
      }
      container.appendChild(row);
    });
  }

  function renderScanSummary() {
    const report = state.report;
    $("#scan-sensitive").textContent = report ? report.sensitiveFound : "0";
    $("#scan-secrets").textContent = report ? report.secretsFound : "0";
    $("#scan-score").textContent = `${state.session?.score ?? 0}/100`;
    $("#scan-time").textContent = report ? fmtDuration(report.durationMs) : "—";

    const errorBox = $("#scan-errors");
    if (report && report.errors && report.errors.length) {
      errorBox.classList.remove("hidden");
      errorBox.textContent = report.errors.join(" · ");
    } else {
      errorBox.classList.add("hidden");
      errorBox.textContent = "";
    }
    updateExportButtons();
  }

  function updateExportButtons() {
    const enabled = Boolean(state.report);
    ["export-txt", "export-json", "export-html", "dash-export-txt", "dash-export-json", "dash-export-html"].forEach(
      (id) => {
        const button = document.getElementById(id);
        if (button) button.disabled = !enabled;
      }
    );
  }

  function renderFindings() {
    const body = $("#findings-body");
    const empty = $("#findings-empty");
    body.replaceChildren();
    const findings = state.report?.findings || [];

    const counts = { All: findings.length, Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    findings.forEach((finding) => {
      if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
    });
    Object.entries(counts).forEach(([key, value]) => {
      const node = document.getElementById(`count-${key}`);
      if (node) node.textContent = String(value);
    });
    $$("#severity-filters [data-filter]").forEach((button) => {
      button.classList.toggle("active", button.dataset.filter === state.filter);
    });

    const query = state.search.trim().toLowerCase();
    const filtered = findings.filter((finding) => {
      if (state.filter !== "All" && finding.severity !== state.filter) return false;
      if (!query) return true;
      const haystack = [
        finding.title,
        finding.detail,
        finding.url,
        finding.file,
        finding.masked,
        finding.snippet,
        finding.severity,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });

    if (!filtered.length) {
      empty.classList.remove("hidden");
      empty.textContent = state.report
        ? query || state.filter !== "All"
          ? "No findings match this filter."
          : "The scan completed with no findings."
        : "No findings yet. Run a scan to populate results.";
      return;
    }
    empty.classList.add("hidden");

    filtered.forEach((finding) => {
      const row = el("tr", "border-b border-slate-800/70 hover:bg-slate-800/30");
      const severityCell = el("td", "px-4 py-3 align-top");
      severityCell.appendChild(
        el("span", `badge ${severityClass(finding.severity)}`, finding.severity)
      );

      const findingCell = el("td", "px-4 py-3 align-top");
      findingCell.appendChild(el("div", "font-medium text-slate-100", finding.title));
      findingCell.appendChild(el("div", "text-xs text-slate-400 mt-0.5", finding.detail));
      if (finding.masked) {
        const revealed = state.revealedSecrets.get(finding.id);
        const valueNode = el(
          "div",
          revealed
            ? "font-mono text-[11px] text-emerald-300 mt-1 break-all select-all"
            : "font-mono text-[11px] text-amber-300/90 mt-1 break-all",
          revealed || finding.masked
        );
        valueNode.dataset.secretValue = finding.id;
        findingCell.appendChild(valueNode);
      }
      if (finding.snippet) {
        findingCell.appendChild(
          el("div", "font-mono text-[10px] text-slate-500 mt-1 break-all", finding.snippet)
        );
      }

      const locationCell = el("td", "px-4 py-3 align-top");
      const location = finding.url || finding.file || "—";
      locationCell.appendChild(
        el("div", "text-[11px] text-blue-300/90 break-all", location)
      );
      if (finding.file && finding.line) {
        locationCell.appendChild(
          el("div", "text-[10px] text-slate-500 mt-0.5", `line ${finding.line}`)
        );
      }
      if (typeof finding.status === "number") {
        locationCell.appendChild(
          el("div", "text-[10px] text-slate-500 mt-0.5", `HTTP ${finding.status}`)
        );
      }

      const actionCell = el("td", "px-4 py-3 align-top text-right");
      const actions = el("div", "flex items-center justify-end gap-1.5");
      if (finding.module === "secret" && finding.masked) {
        const revealButton = el(
          "button",
          "btn btn-ghost text-xs px-2 py-1",
          state.revealedSecrets.has(finding.id) ? "Hide" : "Reveal"
        );
        revealButton.title = "Show or hide the full secret value (exports stay masked)";
        revealButton.addEventListener("click", () => toggleReveal(finding));
        actions.appendChild(revealButton);
      }
      const copyButton = el("button", "btn btn-ghost text-xs px-2 py-1", "Copy");
      copyButton.addEventListener("click", () => copyText(finding.copy || finding.title));
      actions.appendChild(copyButton);
      actionCell.appendChild(actions);

      row.appendChild(severityCell);
      row.appendChild(findingCell);
      row.appendChild(locationCell);
      row.appendChild(actionCell);
      body.appendChild(row);
    });
  }

  async function toggleReveal(finding) {
    if (state.revealedSecrets.has(finding.id)) {
      state.revealedSecrets.delete(finding.id);
      renderFindings();
      return;
    }
    try {
      const raw = await invoke("reveal_secret", { id: finding.id });
      state.revealedSecrets.set(finding.id, raw);
      renderFindings();
      addLog("info", `Revealed full value for: ${finding.title}`);
    } catch (error) {
      toast(errMessage(error), "error");
    }
  }

  function renderFileChecks() {
    const body = $("#file-checks-body");
    const empty = $("#checks-empty");
    body.replaceChildren();
    const checks = (state.report?.fileChecks || [])
      .slice()
      .sort((a, b) => Number(b.found) - Number(a.found));
    $("#checks-count").textContent = `${checks.length} check${checks.length === 1 ? "" : "s"}`;
    if (!checks.length) {
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");
    checks.forEach((check) => {
      const row = el("tr", "border-b border-slate-800/60");
      const resultCell = el("td", "px-4 py-2 align-top");
      resultCell.appendChild(
        el(
          "span",
          `text-[10px] font-bold uppercase ${check.found ? "state-found" : "state-missing"}`,
          check.found ? "Found" : "Not found"
        )
      );
      const pathCell = el("td", "px-4 py-2 align-top");
      pathCell.appendChild(el("div", "font-mono text-xs text-slate-200", check.path));
      pathCell.appendChild(el("div", "text-[10px] text-slate-500 break-all mt-0.5", check.url));
      const statusCell = el(
        "td",
        "px-4 py-2 align-top text-xs text-slate-300",
        typeof check.status === "number" ? `HTTP ${check.status}` : "—"
      );
      const sourceCell = el("td", "px-4 py-2 align-top text-[10px] text-slate-500", check.source);
      row.appendChild(resultCell);
      row.appendChild(pathCell);
      row.appendChild(statusCell);
      row.appendChild(sourceCell);
      body.appendChild(row);
    });
  }

  function renderBruteSummary() {
    const brute = state.brute;
    const resultNode = $("#brute-result");
    if (!brute) {
      if (!state.bruteRunning) {
        resultNode.textContent = "Not started";
        $("#brute-result-banner").classList.add("hidden");
      }
      return;
    }
    const labels = {
      success: "SUCCESS",
      lockout: "Lockout detected",
      stopped: "Stopped",
      failed: "Failed",
      error: "Error",
    };
    resultNode.textContent = labels[brute.status] || brute.status || "Unknown";
    $("#brute-tried").textContent = String(brute.attempts ?? 0);
    if (brute.success) {
      showBruteBanner(
        "success",
        `Login Success: ${brute.username || ""} / ${brute.password || ""}`
      );
      $("#brute-current").textContent = `${brute.username || ""} / ${brute.password || ""}`;
    } else if (brute.status === "lockout") {
      showBruteBanner("warning", "Stopped - possible lockout detected");
    } else if (brute.status === "error") {
      showBruteBanner("error", brute.reason || "The login test failed.");
    } else if (brute.status === "stopped") {
      showBruteBanner("info", "Stopped by user.");
    } else if (brute.status === "failed") {
      showBruteBanner("info", "No valid credentials found.");
    }
  }

  function showBruteBanner(kind, text) {
    const banner = $("#brute-result-banner");
    banner.className = `rounded-lg border px-4 py-3 text-sm result-${kind}`;
    banner.textContent = text;
    banner.classList.remove("hidden");
  }

  // ---------------------------------------------------------------------
  // Sensitive scan
  // ---------------------------------------------------------------------

  function setScanBusy(busy) {
    state.scanning = busy;
    const button = $("#start-scan");
    button.disabled = busy;
    $("#scan-spinner").classList.toggle("hidden", !busy);
    $("#scan-button-text").textContent = busy ? "Scanning…" : "Start Scan";
    $("#scan-progress").classList.toggle("hidden", !busy);
    if (busy) {
      $("#scan-status").textContent = "Scanning… this can take a few seconds";
      $("#scan-status").className = "text-xs text-emerald-300";
    }
  }

  async function startScan() {
    if (state.scanning) return;
    const target = $("#scan-target").value.trim();
    if (!target) {
      toast("Enter a domain or URL first.", "error");
      addLog("error", "Scan refused: target is empty.");
      return;
    }
    localStorage.setItem("leakforce.lastTarget", target);
    state.revealedSecrets.clear();
    setScanBusy(true);
    addLog("info", `Starting sensitive scan: ${target}`);
    try {
      const report = await invoke("run_sensitive_scan", { target });
      state.session = await invoke("get_session");
      renderSession();
      $("#scan-status").textContent = `Complete — ${fmtDuration(report.durationMs)} · score ${report.score}/100`;
      $("#scan-status").className = "text-xs text-emerald-300";
      addLog("success", `Scan complete: ${report.score}/100 · ${report.findings.length} finding(s).`);
      toast(`Scan complete — Leak Score ${report.score}/100`, "success");
      refreshHistory();
    } catch (error) {
      const message = errMessage(error);
      $("#scan-status").textContent = "Scan failed";
      $("#scan-status").className = "text-xs text-red-300";
      addLog("error", message);
      toast(message, "error");
    } finally {
      setScanBusy(false);
      $("#scan-progress").classList.add("hidden");
    }
  }

  async function exportReport(kind) {
    if (!state.report) {
      toast("Run a sensitive scan before exporting.", "error");
      return;
    }
    try {
      const path = await invoke("export_report", { kind });
      addLog("success", `Report saved: ${path}`);
      toast(`Saved: ${path}`, "success");
    } catch (error) {
      const message = errMessage(error);
      addLog("error", message);
      toast(message, "error");
    }
  }

  async function openExports() {
    try {
      const path = await invoke("open_exports_folder");
      addLog("info", `Opened export folder: ${path}`);
    } catch (error) {
      toast(errMessage(error), "error");
    }
  }

  // ---------------------------------------------------------------------
  // Brute force
  // ---------------------------------------------------------------------

  function updateBruteStartState() {
    const checked = $("#brute-authorize").checked;
    const start = $("#brute-start");
    start.disabled = state.bruteRunning || !checked;
    const stop = $("#brute-stop");
    stop.disabled = !state.bruteRunning;
  }

  function setBruteBusy(busy) {
    state.bruteRunning = busy;
    updateBruteStartState();
    ["brute-target", "brute-username", "brute-wordlist-mode", "brute-wordlist-path", "brute-delay", "brute-concurrency"].forEach(
      (id) => {
        const node = document.getElementById(id);
        if (node) node.disabled = busy;
      }
    );
    $("#brute-browse").disabled = busy;
    $("#brute-authorize").disabled = busy;
    if (busy) {
      $("#brute-status").textContent = "Running…";
      $("#brute-status").className = "text-slate-300";
      $("#brute-result").textContent = "Running";
    }
  }

  function resetBruteUI() {
    state.bruteAttempts = 0;
    state.bruteTotal = 0;
    $("#brute-attempts").replaceChildren();
    $("#brute-tried").textContent = "0";
    $("#brute-current").textContent = "—";
    $("#brute-remaining").textContent = "—";
    $("#brute-progress").style.width = "0%";
    $("#brute-progress-text").textContent = "0%";
    $("#brute-result").textContent = "Starting…";
    $("#brute-result-banner").classList.add("hidden");
    $("#brute-form-info").classList.add("hidden");
    $("#brute-form-info").textContent = "";
  }

  async function startBrute() {
    if (state.bruteRunning) return;
    if (!$("#brute-authorize").checked) {
      toast("Confirm the permission checkbox first.", "error");
      return;
    }
    const target = $("#brute-target").value.trim();
    if (!target) {
      toast("Enter the lab login URL.", "error");
      return;
    }
    const mode = $("#brute-wordlist-mode").value;
    const wordlist = mode === "custom" ? $("#brute-wordlist-path").value.trim() : "builtin";
    if (mode === "custom" && !wordlist) {
      toast("Select a custom wordlist file.", "error");
      return;
    }
    const config = {
      target,
      username: $("#brute-username").value.trim(),
      wordlist,
      delayMs: Number($("#brute-delay").value),
      concurrency: Number($("#brute-concurrency").value),
      authorized: true,
    };

    resetBruteUI();
    setBruteBusy(true);
    addLog("warning", `Starting authorized lab login test on ${target}.`);
    try {
      await invoke("run_bruteforce", { config });
      // Final UI state arrives through the "done" event.
    } catch (error) {
      const message = errMessage(error);
      setBruteBusy(false);
      showBruteBanner("error", message);
      $("#brute-status").textContent = "Error";
      $("#brute-result").textContent = "Error";
      addLog("error", message);
      toast(message, "error");
    }
  }

  async function stopBrute() {
    if (!state.bruteRunning) return;
    $("#brute-status").textContent = "Stopping…";
    addLog("warning", "Stop requested. Killing the login worker…");
    try {
      await invoke("stop_bruteforce");
    } catch (error) {
      addLog("error", errMessage(error));
    }
  }

  function handleBruteEvent(event) {
    if (!event || typeof event !== "object") return;
    switch (event.type) {
      case "log":
        addLog(event.level || "info", event.message || "");
        break;
      case "form": {
        const info = $("#brute-form-info");
        info.textContent = `Login form detected: ${String(event.method || "post").toUpperCase()} ${event.action} · user field: ${event.usernameField || "none"} · password field: ${event.passwordField || "password"}`;
        info.classList.remove("hidden");
        addLog("info", "Login form detected and parsed.");
        break;
      }
      case "start":
        state.bruteTotal = Number(event.total) || 0;
        $("#brute-status").textContent = `Running — ${state.bruteTotal} planned attempt(s)`;
        $("#brute-remaining").textContent = fmtSeconds(Number(event.estimatedSeconds) || 0);
        addLog(
          "info",
          `Attempt plan: ${state.bruteTotal} combination(s), ${event.delayMs} ms delay, max ${event.concurrency} thread(s).`
        );
        break;
      case "attempt": {
        state.bruteAttempts += 1;
        const total = Number(event.total) || state.bruteTotal || 0;
        const percent = total > 0 ? Math.min(100, (Number(event.n) / total) * 100) : 0;
        $("#brute-tried").textContent = String(event.n);
        $("#brute-current").textContent = `${event.username || "(none)"} / ${event.password || ""}`;
        $("#brute-remaining").textContent =
          event.remainingText || fmtSeconds(Number(event.remainingSec) || 0);
        $("#brute-progress").style.width = `${percent.toFixed(1)}%`;
        $("#brute-progress-text").textContent = `${Math.round(percent)}%`;
        $("#brute-result").textContent =
          event.result === "success"
            ? "SUCCESS"
            : event.result === "lockout"
            ? "Lockout"
            : "failed";

        const attempt = el(
          "div",
          `truncate attempt-${event.result || "fail"}`,
          `#${event.n} ${event.username || "(none)"} / ${event.password || ""} → HTTP ${event.status ?? 0} · ${event.result || "fail"}`
        );
        attempt.title = event.reason || "";
        const list = $("#brute-attempts");
        list.prepend(attempt);
        while (list.childElementCount > 15) list.lastElementChild.remove();

        const level = event.result === "success" ? "success" : event.result === "lockout" ? "error" : "debug";
        addLog(
          level,
          `Attempt #${event.n}: ${event.username || "(none)"} / ${event.password || ""} → HTTP ${event.status ?? 0} (${event.result || "fail"})`
        );
        if (event.result === "success") {
          showBruteBanner(
            "success",
            `Login Success: ${event.username || ""} / ${event.password || ""}`
          );
          $("#brute-status").textContent = "Success — stopping";
        } else if (event.result === "lockout") {
          showBruteBanner("warning", "Stopped - possible lockout detected");
          $("#brute-status").textContent = "Lockout detected — stopping";
        }
        break;
      }
      case "success":
        showBruteBanner(
          "success",
          `Login Success: ${event.username || ""} / ${event.password || ""}`
        );
        addLog("success", `LOGIN SUCCESS: ${event.username || ""} / ${event.password || ""}`);
        break;
      case "lockout":
        showBruteBanner("warning", "Stopped - possible lockout detected");
        addLog("error", `Lockout detected: ${event.reason || "stopping for safety"}`);
        break;
      case "done": {
        setBruteBusy(false);
        const status = event.status || "error";
        const labels = {
          success: "Success",
          lockout: "Stopped (lockout)",
          stopped: "Stopped",
          failed: "Completed — no valid credentials",
          error: "Error",
        };
        $("#brute-status").textContent = labels[status] || status;
        $("#brute-result").textContent = labels[status] || status;
        $("#brute-tried").textContent = String(event.attempts ?? state.bruteAttempts);
        if (event.success) {
          showBruteBanner(
            "success",
            `Login Success: ${event.username || ""} / ${event.password || ""}`
          );
          toast("Login success found. Testing stopped.", "success");
        } else if (status === "lockout") {
          showBruteBanner("warning", "Stopped - possible lockout detected");
          toast("Stopped: possible lockout detected.", "warning");
        } else if (status === "error") {
          showBruteBanner("error", event.reason || "Login test failed.");
          toast(event.reason || "Login test failed.", "error");
        } else if (status === "stopped") {
          showBruteBanner("info", "Stopped by user.");
        } else {
          showBruteBanner("info", "No valid credentials found.");
        }
        addLog(
          status === "success" ? "success" : status === "error" ? "error" : "info",
          `Login test finished: ${labels[status] || status} · ${event.attempts ?? 0} attempt(s) · ${event.reason || ""}`
        );
        refreshSession();
        refreshHistory();
        break;
      }
      default:
        break;
    }
  }

  // ---------------------------------------------------------------------
  // History
  // ---------------------------------------------------------------------

  async function refreshHistory() {
    try {
      state.history = await invoke("get_history");
      renderHistory();
    } catch (error) {
      addLog("error", `Could not load history: ${errMessage(error)}`);
    }
  }

  function renderHistory() {
    const body = $("#history-body");
    const empty = $("#history-empty");
    body.replaceChildren();
    const history = state.history || [];
    if (!history.length) {
      empty.classList.remove("hidden");
      return;
    }
    empty.classList.add("hidden");
    history.forEach((entry) => {
      const row = el("tr", "border-b border-slate-800/70 hover:bg-slate-800/30");
      row.appendChild(el("td", "px-4 py-3 text-xs text-slate-300", fmtDate(entry.date)));
      row.appendChild(el("td", "px-4 py-3 text-xs font-mono text-emerald-300 break-all", entry.target));
      const typeCell = el("td", "px-4 py-3");
      typeCell.appendChild(
        el(
          "span",
          "badge " + (entry.kind === "Brute Force" ? "sev-high" : "sev-info"),
          entry.kind
        )
      );
      row.appendChild(typeCell);
      const scoreCell = el("td", "px-4 py-3 text-sm font-bold", String(entry.score ?? 0));
      scoreCell.style.color = scoreColor(Number(entry.score) || 0);
      row.appendChild(scoreCell);
      row.appendChild(el("td", "px-4 py-3 text-xs text-slate-400", entry.summary));
      body.appendChild(row);
    });
  }

  async function clearHistory() {
    if (!state.history.length) return;
    if (!window.confirm("Clear all saved scan history? This cannot be undone.")) return;
    try {
      await invoke("clear_history");
      state.history = [];
      renderHistory();
      addLog("info", "History cleared.");
      toast("History cleared.", "info");
    } catch (error) {
      toast(errMessage(error), "error");
    }
  }

  // ---------------------------------------------------------------------
  // Settings and engines
  // ---------------------------------------------------------------------

  async function loadSettings() {
    try {
      state.settings = await invoke("get_settings");
      $("#python-executable").value = state.settings.pythonExecutable || "python";
      $("#java-executable").value = state.settings.javaExecutable || "java";
      $("#engine-override").value = state.settings.pythonEngineOverride || "";
      $("#jar-override").value = state.settings.javaWorkerOverride || "";
      $("#wordlist-path").value = state.settings.wordlistPath || "";
      $("#setting-delay").value = state.settings.delayMs || 1000;
      $("#setting-concurrency").value = state.settings.concurrency || 1;
      setSelectValue($("#brute-delay"), state.settings.delayMs || 1000);
      setSelectValue($("#brute-concurrency"), state.settings.concurrency || 1);
    } catch (error) {
      addLog("error", `Could not load settings: ${errMessage(error)}`);
    }
  }

  function setSelectValue(select, value) {
    const target = String(value);
    if (!Array.from(select.options).some((option) => option.value === target)) {
      const option = document.createElement("option");
      option.value = target;
      option.textContent = `${target} ms — custom default`;
      select.appendChild(option);
    }
    select.value = target;
  }

  async function saveSettings() {
    const settings = {
      pythonExecutable: $("#python-executable").value.trim() || "python",
      javaExecutable: $("#java-executable").value.trim() || "java",
      pythonEngineOverride: $("#engine-override").value.trim(),
      javaWorkerOverride: $("#jar-override").value.trim(),
      wordlistPath: $("#wordlist-path").value.trim(),
      delayMs: Math.max(250, Math.min(10000, Number($("#setting-delay").value) || 1000)),
      concurrency: Math.max(1, Math.min(5, Number($("#setting-concurrency").value) || 1)),
    };
    try {
      state.settings = await invoke("save_settings", { settings });
      $("#setting-delay").value = state.settings.delayMs;
      $("#setting-concurrency").value = state.settings.concurrency;
      $("#settings-status").textContent = "Saved.";
      addLog("success", "Settings saved.");
      toast("Settings saved.", "success");
      testEngines();
    } catch (error) {
      const message = errMessage(error);
      $("#settings-status").textContent = "Save failed.";
      toast(message, "error");
      addLog("error", message);
    }
  }

  async function testEngines() {
    if (state.checkingEngines) return;
    state.checkingEngines = true;
    const button = $("#test-engines");
    button.disabled = true;
    $("#settings-status").textContent = "Checking components…";
    try {
      state.engines = await invoke("check_engines");
      renderEngineStatus();
      $("#settings-status").textContent = state.engines.ready
        ? "All components ready."
        : "Some components need attention.";
      addLog(
        state.engines.ready ? "success" : "warning",
        state.engines.ready
          ? "All engines are ready."
          : "Engine check: some components are missing or not runnable."
      );
    } catch (error) {
      const message = errMessage(error);
      $("#settings-status").textContent = "Engine check failed.";
      addLog("error", message);
      setEngineIndicator(false, "Engine check failed");
    } finally {
      state.checkingEngines = false;
      button.disabled = false;
    }
  }

  function renderEngineStatus() {
    const container = $("#engine-status");
    if (!container) return;
    container.replaceChildren();
    const status = state.engines;
    if (!status) {
      container.appendChild(el("div", "text-xs text-slate-500", "Checking components…"));
      return;
    }
    const rows = [
      { label: "Python", ok: status.pythonOk, detail: status.pythonVersion, path: "" },
      { label: "Java", ok: status.javaOk, detail: status.javaVersion, path: "" },
      { label: "Python engine", ok: status.engineOk, detail: status.engineOk ? "File found" : "Missing", path: status.enginePath },
      { label: "Java worker JAR", ok: status.jarOk, detail: status.jarOk ? "File found" : "Missing — run java-worker\\build.ps1", path: status.jarPath },
      { label: "Wordlist", ok: status.wordlistOk, detail: status.wordlistOk ? "File found" : "Missing", path: status.wordlistPath },
    ];
    rows.forEach((row) => {
      const wrapper = el("div", "rounded-lg border border-slate-800 bg-slate-900/30 px-3 py-2.5");
      const line = el("div", "flex items-center gap-2");
      line.appendChild(el("span", `w-2 h-2 rounded-full ${row.ok ? "dot-ok" : "dot-bad"}`));
      line.appendChild(el("span", "text-sm font-medium", row.label));
      line.appendChild(el("span", "text-xs text-slate-500 ml-auto", row.detail));
      wrapper.appendChild(line);
      if (row.path) {
        wrapper.appendChild(el("div", "text-[10px] font-mono text-slate-500 mt-1 break-all", row.path));
      }
      container.appendChild(wrapper);
    });
    setEngineIndicator(
      status.ready,
      status.ready ? "Engines ready" : "Engine setup needed"
    );
  }

  async function loadAppInfo() {
    try {
      state.appInfo = await invoke("get_app_info");
      renderAppInfo();
    } catch (error) {
      addLog("warning", `Could not load app info: ${errMessage(error)}`);
    }
  }

  function renderAppInfo() {
    const node = $("#app-info");
    if (!node || !state.appInfo) return;
    node.textContent = `LeakForce v${state.appInfo.version} · Data: ${state.appInfo.dataDir} · Exports: ${state.appInfo.exportsDir}`;
  }

  async function browseWordlist(inputId) {
    try {
      const path = await invoke("pick_wordlist");
      if (path) {
        const input = document.getElementById(inputId);
        if (input) input.value = path;
        if (inputId === "brute-wordlist-path") {
          $("#brute-wordlist-mode").value = "custom";
          $("#brute-custom-wordlist").classList.remove("hidden");
        }
      }
    } catch (error) {
      toast(errMessage(error), "error");
    }
  }

  // ---------------------------------------------------------------------
  // Event bindings
  // ---------------------------------------------------------------------

  function bindEvents() {
    $$("[data-nav]").forEach((button) => {
      button.addEventListener("click", () => switchView(button.dataset.nav));
    });

    $("#dash-new-scan").addEventListener("click", () => {
      switchView("sensitive");
      $("#scan-target").focus();
    });
    $("#dash-empty-start").addEventListener("click", () => switchView("sensitive"));
    $("#dash-view-findings").addEventListener("click", () => switchView("sensitive"));

    $("#start-scan").addEventListener("click", startScan);
    $("#scan-target").addEventListener("keydown", (event) => {
      if (event.key === "Enter") startScan();
    });

    $("#finding-search").addEventListener("input", (event) => {
      state.search = event.target.value;
      renderFindings();
    });
    $$("#severity-filters [data-filter]").forEach((button) => {
      button.addEventListener("click", () => {
        state.filter = button.dataset.filter;
        renderFindings();
      });
    });

    ["export-txt", "dash-export-txt"].forEach((id) =>
      document.getElementById(id)?.addEventListener("click", () => exportReport("txt"))
    );
    ["export-json", "dash-export-json"].forEach((id) =>
      document.getElementById(id)?.addEventListener("click", () => exportReport("json"))
    );
    ["export-html", "dash-export-html"].forEach((id) =>
      document.getElementById(id)?.addEventListener("click", () => exportReport("html"))
    );
    $("#open-exports").addEventListener("click", openExports);
    $("#dash-open-exports").addEventListener("click", openExports);

    $("#brute-authorize").addEventListener("change", updateBruteStartState);
    $("#brute-start").addEventListener("click", startBrute);
    $("#brute-stop").addEventListener("click", stopBrute);
    $("#brute-wordlist-mode").addEventListener("change", () => {
      $("#brute-custom-wordlist").classList.toggle(
        "hidden",
        $("#brute-wordlist-mode").value !== "custom"
      );
    });
    $("#brute-browse").addEventListener("click", () => browseWordlist("brute-wordlist-path"));
    $("#browse-settings-wordlist").addEventListener("click", () => browseWordlist("wordlist-path"));

    $("#refresh-history").addEventListener("click", refreshHistory);
    $("#clear-history").addEventListener("click", clearHistory);

    $("#save-settings").addEventListener("click", saveSettings);
    $("#test-engines").addEventListener("click", testEngines);

    $("#clear-log").addEventListener("click", () => {
      $("#log").replaceChildren();
      $("#log-count").textContent = "0";
    });

    updateBruteStartState();
  }

  async function bindBackendEvents() {
    try {
      await listen("scan-log", (event) => {
        const payload = event.payload || {};
        addLog(payload.level || "info", payload.message || "");
      });
      await listen("brute-event", (event) => handleBruteEvent(event.payload));
    } catch (error) {
      addLog("warning", `Could not subscribe to backend events: ${errMessage(error)}`);
    }
  }

  async function init() {
    bindEvents();
    await bindBackendEvents();
    addLog("info", "LeakForce v1.0 ready. Authorized lab use only.");

    const savedTarget = localStorage.getItem("leakforce.lastTarget");
    if (savedTarget) $("#scan-target").value = savedTarget;
    $("#brute-target").placeholder = "http://localhost/dvwa/login.php";

    await Promise.allSettled([loadSettings(), refreshSession(), refreshHistory(), loadAppInfo()]);
    testEngines();
    switchView("dashboard");

    if (!hasTauri) {
      addLog("error", "Tauri API not found. Open this UI through the LeakForce desktop app.");
      toast("Run the app with Tauri (npm run dev) for full functionality.", "error");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
