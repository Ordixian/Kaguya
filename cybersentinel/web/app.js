// Kaguya dashboard — polls the live API. No mock data: everything
// rendered here comes straight from /api/* on the running monitor.
(function () {
  "use strict";

  const POLL_MS = 3000;
  const LS_THEME = "kaguya.theme";   // "light" | "dark" | (unset => follow OS)
  const LS_MUTED = "kaguya.muted";   // "1" | "0"
  let alertStatusFilter = "";
  let eventSearch = "";

  let muted = false;
  let seenAlertIds = null;           // null until first load (don't toast history)
  let alertMoodUntil = 0;            // timestamp: keep mascot in "alert" mood until

  const $ = (sel) => document.querySelector(sel);
  const el = (tag, cls, html) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (html != null) e.innerHTML = html;
    return e;
  };
  const esc = (s) => String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const ago = (ts) => {
    const d = Math.max(0, Date.now() / 1000 - ts);
    if (d < 60) return Math.floor(d) + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  };
  const dur = (secs) => {
    secs = Math.max(0, Math.floor(secs));
    const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600);
    const m = Math.floor((secs % 3600) / 60), s = secs % 60;
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${s}s`;
    return `${s}s`;
  };

  async function api(path, opts) {
    opts = Object.assign({}, opts);
    if (opts.method === "POST") {   // custom header = proof the request came from this dashboard
      opts.headers = Object.assign({ "X-Kaguya-Request": "1" }, opts.headers);
    }
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error(r.status + " " + path);
    return r.json();
  }
  // POST JSON and return the parsed reply even on 4xx (the server explains why)
  async function post(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "X-Kaguya-Request": "1", "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    let j = {};
    try { j = await r.json(); } catch (_) {}
    if (!r.ok && j.ok === undefined) j.ok = false;
    if (!r.ok && !j.message) j.message = j.error || ("request failed (" + r.status + ")");
    return j;
  }

  // ---- theme -------------------------------------------------------------
  function storedTheme() {
    try { return localStorage.getItem(LS_THEME); } catch (_) { return null; }
  }
  function effectiveTheme() {
    const t = storedTheme();
    if (t === "light" || t === "dark") return t;
    // follow OS when the viewer hasn't chosen
    return "dark";   // obsidian is the default console look
  }
  function applyTheme() {
    const t = storedTheme();
    const root = document.documentElement;
    root.setAttribute("data-theme", t === "light" ? "light" : "dark");
    const btn = $("#theme-btn");
    if (btn) btn.textContent = effectiveTheme() === "dark" ? "☾" : "☀";
  }
  function toggleTheme() {
    const next = effectiveTheme() === "dark" ? "light" : "dark";
    try { localStorage.setItem(LS_THEME, next); } catch (_) {}
    applyTheme();
  }

  // ---- wallpaper (optional image the viewer drops into web/) ------------
  const LS_WALL = "kaguya.wallpaper";
  let wallUrl = null;
  function findWallpaper(cb) {
    const names = ["wallpaper.mp4", "wallpaper.webm", "wallpaper.jpg", "wallpaper.jpeg", "wallpaper.png", "wallpaper.webp"];
    const next = (i) => {
      if (i >= names.length) return cb(null);
      if (/\.(mp4|webm)$/.test(names[i])) {
        fetch(names[i], { method: "GET", headers: { Range: "bytes=0-0" } })
          .then(r => (r.ok ? cb(names[i]) : next(i + 1)), () => next(i + 1));
        return;
      }
      const p = new Image();
      p.onload = () => cb(names[i]);
      p.onerror = () => next(i + 1);
      p.src = names[i];
    };
    next(0);
  }
  function setWallpaper(on, quiet, temp) {
    const box = $("#wall-toggle");
    const finish = (enabled) => {
      document.body.classList.toggle("wall-on", enabled);
      if (box) box.checked = enabled;
      if (!temp) { try { localStorage.setItem(LS_WALL, enabled ? "1" : "0"); } catch (_) {} }
    };
    const vid = $("#wall-video"), wp = $("#wallpaper");
    if (!on) { try { vid.pause(); } catch (_) {} return finish(false); }
    const show = () => {
      const isVideo = /\.(mp4|webm)$/.test(wallUrl);
      wp.classList.toggle("is-video", isVideo);
      if (isVideo) {
        wp.style.backgroundImage = "";
        if (!vid.getAttribute("src")) vid.src = wallUrl;
        vid.muted = true;
        const p = vid.play(); if (p && p.catch) p.catch(() => {});
      } else {
        try { vid.pause(); } catch (_) {}
        wp.style.backgroundImage = `url("${wallUrl}")`;
      }
      finish(true);
    };
    if (wallUrl) return show();
    findWallpaper((name) => {
      if (!name) {
        finish(false);
        if (!quiet) notice("No wallpaper image found", "Save an image (wallpaper.jpg / .png / .webp) or video (wallpaper.mp4 / .webm) in cybersentinel/web/, then flip the switch again.", "info");
        return;
      }
      wallUrl = name; show();
    });
  }

  // hold anywhere on the dashboard (not on a control) to hide the UI and see the wallpaper
  (function peekInit() {
    const HOLD_MS = 350, MOVE_PX = 8;
    let timer = null, sx = 0, sy = 0, peeking = false, tempOn = false;
    const skip = "button, a, input, select, textarea, label, code, .mascot, .dl-pop, .toast, .explain, .members";
    const start = () => {
      peeking = true;
      if (!document.body.classList.contains("wall-on")) { tempOn = true; setWallpaper(true, true, true); }
      document.body.classList.add("peek");
      try { getSelection().removeAllRanges(); } catch (_) {}
    };
    const stop = () => {
      clearTimeout(timer); timer = null;
      if (!peeking) return;
      peeking = false;
      document.body.classList.remove("peek");
      if (tempOn) { tempOn = false; setWallpaper(false, true, true); }
    };
    document.addEventListener("pointerdown", (e) => {
      if (e.button > 0 || (e.target.closest && e.target.closest(skip))) return;
      sx = e.clientX; sy = e.clientY;
      clearTimeout(timer);
      timer = setTimeout(start, HOLD_MS);
    });
    document.addEventListener("pointermove", (e) => {
      if (timer && Math.hypot(e.clientX - sx, e.clientY - sy) > MOVE_PX) { clearTimeout(timer); timer = null; }
    });
    ["pointerup", "pointercancel", "blur"].forEach(t => window.addEventListener(t, stop));
    document.addEventListener("contextmenu", (e) => { if (peeking || timer) e.preventDefault(); });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") stop(); });
  })();

  // ---- mute / chime ------------------------------------------------------
  function applyMute() {
    const btn = $("#mute-btn");
    if (!btn) return;
    btn.textContent = muted ? "♪̸" : "♪";
    btn.classList.toggle("muted", muted);
    btn.title = (muted ? "Unmute" : "Mute") + " alert sound (M)";
  }
  function toggleMute() {
    muted = !muted;
    try { localStorage.setItem(LS_MUTED, muted ? "1" : "0"); } catch (_) {}
    applyMute();
  }
  let audioCtx = null;
  function chime(critical) {
    if (muted) return;
    try {
      audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      const now = audioCtx.currentTime;
      // a soft two-note bell; a touch more urgent for critical
      const notes = critical ? [880, 1174.7, 880] : [659.25, 987.77];
      notes.forEach((f, i) => {
        const o = audioCtx.createOscillator();
        const g = audioCtx.createGain();
        o.type = "sine"; o.frequency.value = f;
        const t = now + i * 0.16;
        g.gain.setValueAtTime(0, t);
        g.gain.linearRampToValueAtTime(0.18, t + 0.02);
        g.gain.exponentialRampToValueAtTime(0.0001, t + 0.42);
        o.connect(g); g.connect(audioCtx.destination);
        o.start(t); o.stop(t + 0.45);
      });
    } catch (_) {}
  }

  // ---- mascot (Mascot) -------------------------------------------------
  function initMascot() {
    const box = $("#mascot"), img = $("#mascot-img");
    if (!box || !img) return;
    // try calm image; if it loads, reveal it, else keep placeholder
    const probe = new Image();
    probe.onload = () => { img.src = "mascot-calm.png"; box.classList.add("has-img"); };
    probe.onerror = () => { box.classList.remove("has-img"); };
    probe.src = "mascot-calm.png";
    box.addEventListener("click", expandMascot);
    box.addEventListener("dblclick", collapseMascot);
    $("#mascot-backdrop").addEventListener("dblclick", collapseMascot);
  }
  // click -> enlarge and play the animated gif; double-click (or Esc) -> back to the corner
  let gifOk = null;                      // null = unknown, true/false after probing
  function probeGif(cb) {
    if (gifOk !== null) return cb(gifOk);
    const p = new Image();
    p.onload = () => { gifOk = true; cb(true); };
    p.onerror = () => { gifOk = false; cb(false); };
    p.src = "mascot.gif";
  }
  function expandMascot() {
    const box = $("#mascot"), img = $("#mascot-img");
    if (!box || box.classList.contains("expanded")) return;   // 2nd click of a dblclick lands here
    box.classList.add("expanded");
    $("#mascot-backdrop").classList.add("show");
    if (box.classList.contains("has-img") && img) {
      probeGif((ok) => {
        if (!box.classList.contains("expanded")) return;
        if (ok) { img.src = "mascot.gif?t=" + Date.now(); }   // cache-bust so the gif restarts
        else mascotSay("Add mascot.gif next to mascot-calm.png to see me move!");
      });
    }
  }
  function collapseMascot() {
    const box = $("#mascot");
    if (!box || !box.classList.contains("expanded")) return;
    box.classList.remove("expanded");
    $("#mascot-backdrop").classList.remove("show");
    const img = $("#mascot-img");
    if (img && box.classList.contains("has-img")) {
      img.src = "mascot-calm.png";
      setMascotMood();
    }
  }
  let bubbleTimer = null;
  function mascotSay(text) {
    const box = $("#mascot"), bubble = $("#mascot-bubble");
    if (!box || !bubble) return;
    bubble.textContent = text;
    box.classList.add("talking");
    clearTimeout(bubbleTimer);
    bubbleTimer = setTimeout(() => box.classList.remove("talking"), 4500);
  }
  function setMascotMood() {
    const box = $("#mascot"), img = $("#mascot-img");
    if (!box) return;
    const alert = Date.now() < alertMoodUntil;
    box.dataset.mood = alert ? "alert" : "calm";
    if (!alert) box.classList.remove("alert-tint");
    if (box.classList.contains("expanded")) return;   // keep the gif playing
    if (box.classList.contains("has-img") && img) {
      const want = alert ? "mascot-alert.png" : "mascot-calm.png";
      if (!img.src.endsWith(want)) {
        // only swap if the alert image exists; otherwise reuse calm
        if (alert) {
          const probe = new Image();
          probe.onload = () => { img.src = want; box.classList.remove("alert-tint"); };
          // no mascot-alert.png supplied: tint the calm image red instead
          probe.onerror = () => { box.classList.add("alert-tint"); };
          probe.src = want;
        } else { img.src = want; box.classList.remove("alert-tint"); }
      }
    }
  }
  function triggerAlertMood(ms) { alertMoodUntil = Date.now() + (ms || 15000); setMascotMood(); }

  // ---- toasts ------------------------------------------------------------
  function toast(a) {
    const stack = $("#toast-stack");
    if (!stack) return;
    const t = el("div", "toast " + (a.severity === "critical" ? "critical" : ""));
    t.appendChild(el("div", "t-ico", a.severity === "critical" ? "‼" : "!"));
    const b = el("div", "t-body");
    b.appendChild(el("div", "t-title", esc(a.title)));
    if (a.description) b.appendChild(el("div", "t-desc", esc(a.description)));
    b.appendChild(el("div", "t-meta", `${esc(a.severity.toUpperCase())} · ${esc(a.rule)} · ${esc(a.host)}`));
    t.appendChild(b);
    stack.appendChild(t);
    requestAnimationFrame(() => t.classList.add("show"));
    setTimeout(() => {
      t.classList.remove("show");
      setTimeout(() => t.remove(), 400);
    }, 8000);
  }

  // longer-lived message (used for block / safe results); optional copyable command
  function notice(title, desc, kind, cmd) {
    const stack = $("#toast-stack");
    if (!stack) return;
    const t = el("div", "toast " + (kind === "bad" ? "critical" : kind === "ok" ? "ok" : ""));
    t.appendChild(el("div", "t-ico", kind === "bad" ? "!" : kind === "ok" ? "✓" : "i"));
    const b = el("div", "t-body");
    b.appendChild(el("div", "t-title", esc(title)));
    if (desc) b.appendChild(el("div", "t-desc wrap", esc(desc)));
    if (cmd) b.appendChild(el("code", "t-cmd", esc(cmd)));
    t.appendChild(b);
    t.onclick = () => { t.classList.remove("show"); setTimeout(() => t.remove(), 300); };
    stack.appendChild(t);
    requestAnimationFrame(() => t.classList.add("show"));
    setTimeout(() => { t.classList.remove("show"); setTimeout(() => t.remove(), 400); }, cmd ? 30000 : 9000);
  }

  // ---- renderers ---------------------------------------------------------
  function renderTiles(stats, status) {
    const sev = stats.open_alerts_by_severity || {};
    const high = (sev.high || 0) + (sev.critical || 0);
    const h = stats.health || {};
    const tiles = [
      { ico: "", k: "Host health", v: h.title || "—", sub: h.message || "", cls: "health h-" + (h.level || "clear"), score: h.score },
      { ico: "", k: "Open alerts", v: stats.alerts_open, sub: "needs review", cls: stats.alerts_open ? "alert" : "" },
      { ico: "", k: "High / Critical", v: high, sub: "elevated severity", cls: high ? "alert" : "" },
      { ico: "", k: "Events seen", v: stats.events_total, sub: "since start" },
      { ico: "", k: "Sweeps", v: status.sweeps || 0, sub: status.interval_sec + "s interval" },
      { ico: "", k: "Collectors", v: (status.collectors || []).length, sub: (status.collectors || []).map(c => c.name).join(", ") },
    ];
    const root = $("#tiles");
    root.innerHTML = "";
    tiles.forEach(t => {
      const d = el("div", "tile " + (t.cls || ""));
      d.appendChild(el("div", "ico", t.ico));
      d.appendChild(el("div", "k", esc(t.k)));
      d.appendChild(el("div", "v", esc(t.v) + (t.score != null ? ` <span class="score">${t.score}/100</span>` : "")));
      d.appendChild(el("div", "sub", esc(t.sub)));
      root.appendChild(d);
    });
    const strip = $("#sevstrip");
    if (strip) {
      strip.innerHTML = ["critical", "high", "medium", "low", "info"].map(s =>
        `<span class="sv"><span class="sq ${s}"></span>${s} <b>${sev[s] || 0}</b></span>`).join("")
        + `<span class="sv">open alerts by severity</span>`;
    }
  }

  function renderGreeting(status) {
    const h = new Date().getHours();
    const part = h < 5 ? "Still up" : h < 12 ? "Good morning"
      : h < 18 ? "Good afternoon" : "Good evening";
    const line = $("#greet-line");
    if (line) line.textContent = `${part} — endpoint monitoring active`;
    const sub = $("#greet-sub");
    if (sub) {
      const bits = [];
      if (status.host) bits.push("host " + status.host);
      if (status.running) bits.push("monitoring");
      else bits.push("stopped");
      if (status.started_at) bits.push("up " + dur(Date.now() / 1000 - status.started_at));
      sub.textContent = bits.join(" · ");
    }
  }

  // ATT&CK technique each built-in detection rule corresponds to
  const MITRE = {
    ssh_bruteforce: ["T1110", "Brute Force"],
    privilege_event: ["T1548", "Abuse Elevation Control"],
    suspicious_exec_path: ["T1059", "Command & Scripting Interpreter"],
    file_integrity: ["T1565", "Data Manipulation"],
    new_listen_port: ["T1571", "Non-Standard Port"],
    known_bad_port: ["T1571", "Non-Standard Port"],
    connection_fanout: ["T1046", "Network Service Discovery"],
  };

  const openExplain = new Set();     // alert ids whose explanation is expanded (survives the 3s re-render)

  function explainBlock(ex) {
    const box = el("div", "explain");
    const sec = (title, inner) => {
      const d = el("div");
      d.appendChild(el("h4", null, esc(title)));
      d.appendChild(inner);
      box.appendChild(d);
    };
    sec("What this means", el("p", null, esc(ex.what)));
    const cause = el("ul");
    (ex.cause || []).forEach(c => cause.appendChild(el("li", null, esc(c))));
    sec("What probably caused it", cause);
    const risk = el("p", null, `<span class="warn">${esc(ex.risk)}</span> <span class="safe">It's probably fine if ${esc(ex.safe_if)}</span>`);
    sec("How worried should I be?", risk);
    const fix = el("ol");
    (ex.fix || []).forEach(f => {
      const li = el("li", null, esc(f.text));
      if (f.cmd) li.appendChild(el("code", null, esc(f.cmd)));
      fix.appendChild(li);
    });
    sec("How to fix it", fix);
    return box;
  }

  const openGroups = new Set();      // group keys whose member list is expanded
  let canBlock = true;

  // collapse repeats (same rule + same subject) into one card, newest first
  function groupAlerts(alerts) {
    const map = new Map();
    alerts.forEach(a => {
      const key = a.group || a.id;
      if (!map.has(key)) map.set(key, { key, items: [] });
      map.get(key).items.push(a);
    });
    return [...map.values()];   // alerts arrive newest-first, so order is preserved
  }

  async function bulk(ids, action) {
    if (!ids.length) return;
    try { await post("/api/alerts/bulk/" + action, { ids }); } catch (_) {}
    refresh();
  }

  async function markSafe(g) {
    const a = g.items[0];
    const label = a.group_label || a.title;
    if (!confirm(`Mark as safe?\n\nKaguya will stop alerting you about ${label}, and the ${g.items.length} existing matching alert(s) will be resolved.\n\nYou can undo this any time from "Safe list".`)) return;
    const r = await post(`/api/alerts/${a.id}/safe`);
    notice(r.ok ? "Marked as safe" : "Couldn't mark as safe", r.ok ? `No more alerts about ${r.label}. Undo from Safe list.` : r.message, r.ok ? "ok" : "bad");
    refresh();
  }

  async function blockIp(g) {
    const a = g.items[0], ip = (a.data || {}).ip;
    if (!confirm(`Block ${ip}?\n\nThis adds a firewall rule so that address can no longer reach this computer. Make sure it isn't you or someone you trust.\n\nYou can unblock it later from "Safe list".`)) return;
    let r = await post(`/api/alerts/${a.id}/block`);
    if (!r.ok && r.needs_private_confirm) {
      if (!confirm(r.message + "\n\nBlock it anyway?")) return;
      r = await post(`/api/alerts/${a.id}/block`, { confirm_private: true });
    }
    if (r.ok) notice("IP blocked", r.message, "ok");
    else notice("Not blocked", r.message, "bad", r.manual);
    refresh();
  }

  function groupCard(g) {
    const a = g.items[0], n = g.items.length;
    const open = g.items.filter(x => x.status === "open");
    const status = open.length ? "open" : a.status;
    const card = el("div", "card");
    card.appendChild(el("div", "bar " + a.severity));
    const body = el("div", "body");
    body.appendChild(el("div", "title", esc(a.title) + (n > 1 ? ` <span class="count">×${n}</span>` : "")));
    const desc = n > 1
      ? `${n} similar alerts, first seen ${ago(g.items[n - 1].ts)}. Latest: ${a.description || ""}`
      : a.description;
    if (desc) body.appendChild(el("div", "desc", esc(desc)));
    const meta = el("div", "meta");
    meta.appendChild(el("span", null, esc(a.rule)));
    const mt = MITRE[a.rule];
    if (mt) { const m = el("span", "mitre", esc(mt[0])); m.title = "MITRE ATT&CK: " + mt[1]; meta.appendChild(m); }
    meta.appendChild(el("span", null, esc(a.host)));
    meta.appendChild(el("span", null, ago(a.ts)));
    if (status !== "open") meta.appendChild(el("span", "status-tag " + status, esc(status)));
    else if (n > 1 && open.length < n) meta.appendChild(el("span", "status-tag open", `${open.length} open`));
    body.appendChild(meta);

    const tools = el("div", "card-tools");
    if (a.explain) {
      const tog = el("button", "explain-toggle");
      const panel = explainBlock(a.explain);
      const sync = () => {
        const o = openExplain.has(g.key);
        panel.hidden = !o;
        tog.textContent = o ? "Hide analysis" : "Analysis & remediation";
      };
      tog.onclick = () => { openExplain.has(g.key) ? openExplain.delete(g.key) : openExplain.add(g.key); sync(); };
      sync();
      tools.appendChild(tog);
      body.appendChild(tools);
      body.appendChild(panel);
    }
    if (n > 1) {
      const more = el("button", "explain-toggle ghost");
      const list = el("div", "members");
      g.items.slice(0, 50).forEach(m => list.appendChild(el("div", "member",
        `<span class="sev ${m.severity}">${esc(m.severity)}</span> ${esc(m.title)} <span class="m-time">${ago(m.ts)}${m.status !== "open" ? " · " + esc(m.status) : ""}</span>`)));
      if (n > 50) list.appendChild(el("div", "member", `…and ${n - 50} older`));
      const sync = () => {
        const o = openGroups.has(g.key);
        list.hidden = !o;
        more.textContent = o ? "Hide " + n : "Show all " + n;
      };
      more.onclick = () => { openGroups.has(g.key) ? openGroups.delete(g.key) : openGroups.add(g.key); sync(); };
      sync();
      tools.appendChild(more);
      if (!tools.parentNode) body.appendChild(tools);
      body.appendChild(list);
    }
    card.appendChild(body);

    const right = el("div", "right");
    right.appendChild(el("div", "sev " + a.severity, esc(a.severity)));
    const actions = el("div", "actions");
    const btn = (label, fn, cls) => { const b = el("button", cls || null, label); b.onclick = fn; return b; };
    if (open.length) {
      const ids = open.map(x => x.id);
      actions.append(btn(n > 1 ? "ack all" : "ack", () => bulk(ids, "ack")),
                     btn(n > 1 ? "resolve all" : "resolve", () => bulk(ids, "resolve")));
    } else {
      actions.append(btn("reopen", () => bulk(g.items.map(x => x.id), "reopen")));
    }
    actions.append(btn("allow", () => markSafe(g), "safe-btn"));
    if (a.rule === "ssh_bruteforce" && canBlock && (a.data || {}).ip)
      actions.append(btn("block IP", () => blockIp(g), "block-btn"));
    right.appendChild(actions);
    card.appendChild(right);
    return card;
  }

  const openEventExplain = new Set();

  function eventCard(e) {
    const card = el("div", "card");
    card.appendChild(el("div", "bar " + e.severity));
    const body = el("div", "body");
    body.appendChild(el("div", "title", esc(e.title)));
    if (e.description) body.appendChild(el("div", "desc", esc(e.description)));
    const meta = el("div", "meta");
    meta.appendChild(el("span", null, esc(e.category)));
    meta.appendChild(el("span", null, esc(e.source)));
    meta.appendChild(el("span", null, ago(e.ts)));
    body.appendChild(meta);
    if (e.explain) {
      const x = e.explain;
      const tog = el("button", "explain-toggle small");
      const panel = el("div", "explain", `<p>${esc(x.what)}</p>` +
        (x.extra ? `<p>${esc(x.extra)}</p>` : "") +
        `<p class="safe">Is it a problem? ${esc(x.normal)}</p>`);
      const sync = () => {
        const o = openEventExplain.has(e.id);
        panel.hidden = !o;
        tog.textContent = o ? "Hide" : "Details";
      };
      tog.onclick = () => { openEventExplain.has(e.id) ? openEventExplain.delete(e.id) : openEventExplain.add(e.id); sync(); };
      sync();
      body.append(tog, panel);
    }
    card.appendChild(body);
    const right = el("div", "right");
    right.appendChild(el("div", "sev " + e.severity, esc(e.severity)));
    card.appendChild(right);
    return card;
  }

  async function act(id, action) {
    try {
      await api(`/api/alerts/${id}/${action}`, { method: "POST" });
      refresh();
    } catch (_) {}
  }

  // ---- new-alert detection (chime + toast + mascot) ----------------------
  function handleNewAlerts(alerts) {
    const ids = new Set(alerts.map(a => a.id));
    if (seenAlertIds === null) { seenAlertIds = ids; return; }  // prime, no toast
    const fresh = alerts.filter(a =>
      !seenAlertIds.has(a.id) &&
      (a.severity === "high" || a.severity === "critical") &&
      a.status === "open");
    if (fresh.length) {
      const critical = fresh.some(a => a.severity === "critical");
      chime(critical);
      triggerAlertMood(18000);
      mascotSay(fresh.length === 1 ? "Careful — something's off!" : `${fresh.length} new alerts!`);
      fresh.slice(0, 4).forEach(toast);
    }
    seenAlertIds = ids;
  }

  // ---- poll loop ---------------------------------------------------------
  async function refresh() {
    try {
      const [status, stats, alerts, events] = await Promise.all([
        api("/api/status"),
        api("/api/stats"),
        api("/api/alerts?limit=100" + (alertStatusFilter ? "&status=" + alertStatusFilter : "")),
        api("/api/events?limit=150"),
      ]);

      $("#live-dot").className = "dot " + (status.running ? "live" : "dead");
      $("#status-text").textContent = status.running ? "monitoring" : "stopped";
      $("#tier-pill").textContent = status.tier || "—";
      const tf = $("#tier-foot"); if (tf) tf.textContent = status.tier || "community";
      $("#host-label").textContent = status.host ? "host: " + status.host : "";
      $("#last-sweep").textContent = status.last_sweep
        ? "last sweep " + ago(status.last_sweep) : "";

      canBlock = status.can_block !== false;
      renderGreeting(status);
      renderTiles(stats, status);

      // new-alert effects run against the unfiltered open picture
      handleNewAlerts(alerts);
      setMascotMood();

      const aRoot = $("#alerts");
      aRoot.innerHTML = "";
      if (!alerts.length) aRoot.appendChild(el("div", "empty", "<span class='big'>All clear</span>No alerts in this view."));
      else groupAlerts(alerts).forEach(g => aRoot.appendChild(groupCard(g)));

      const filtered = eventSearch
        ? events.filter(e => (e.category + " " + e.title).toLowerCase().includes(eventSearch))
        : events;
      const eRoot = $("#events");
      eRoot.innerHTML = "";
      if (!filtered.length) eRoot.appendChild(el("div", "empty", "<span class='big'>Listening</span>Telemetry will appear here as it is collected."));
      else filtered.forEach(e => eRoot.appendChild(eventCard(e)));
    } catch (err) {
      $("#live-dot").className = "dot dead";
      $("#status-text").textContent = "disconnected";
    }
  }

  // ---- wiring ------------------------------------------------------------
  document.querySelectorAll("#alert-filters button").forEach(b => {
    b.onclick = () => {
      document.querySelectorAll("#alert-filters button").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      alertStatusFilter = b.dataset.status;
      refresh();
    };
  });
  $("#event-search").addEventListener("input", (e) => {
    eventSearch = e.target.value.trim().toLowerCase();
    refresh();
  });

  $("#wall-toggle").addEventListener("change", (e) => setWallpaper(e.target.checked));
  $("#theme-btn").addEventListener("click", toggleTheme);
  $("#mute-btn").addEventListener("click", toggleMute);
  $("#refresh-btn").addEventListener("click", () => {
    const btn = $("#refresh-btn");
    btn.classList.remove("spin"); void btn.offsetWidth; btn.classList.add("spin");
    refresh();
  });

  // ---- download history ----
  const dlPop = $("#dl-pop"), dlBtn = $("#dl-btn");
  function setDl(open) { dlPop.hidden = !open; dlBtn.setAttribute("aria-expanded", String(open)); }
  dlBtn.addEventListener("click", (e) => { e.stopPropagation(); setSafe(false); setDl(dlPop.hidden); });
  dlPop.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => setDl(false));
  $("#dl-period").addEventListener("change", (e) => { $("#dl-custom").hidden = e.target.value !== "custom"; });
  $("#dl-go").addEventListener("click", () => {
    const period = $("#dl-period").value, fmt = $("#dl-format").value;
    let qs = "format=" + encodeURIComponent(fmt);
    if (period === "custom") {
      const f = $("#dl-from").value, t = $("#dl-to").value;
      if (!f && !t) { alert("Pick a start and/or end date first."); return; }
      if (f) qs += "&from=" + new Date(f).getTime() / 1000;
      if (t) qs += "&to=" + new Date(t).getTime() / 1000;
    } else qs += "&period=" + encodeURIComponent(period);
    window.location.href = "/api/report?" + qs;   // server replies with an attachment
    setDl(false);
  });

  // ---- safe list + blocked IPs ----
  const safePop = $("#safe-pop"), safeBtn = $("#safe-btn");
  function setSafe(open) {
    safePop.hidden = !open;
    safeBtn.setAttribute("aria-expanded", String(open));
    if (open) loadSafe();
  }
  async function loadSafe() {
    const [allow, blocks] = await Promise.all([api("/api/allowlist"), api("/api/blocks")]);
    safeBtn.textContent = `Safe list${allow.length + blocks.length ? " (" + (allow.length + blocks.length) + ")" : ""}`;
    const root = $("#safe-body");
    root.innerHTML = "";
    root.appendChild(el("h4", null, "Marked as safe (no alerts)"));
    if (!allow.length) root.appendChild(el("div", "safe-empty", "Nothing yet. Use “allow” on an alert for something you trust."));
    allow.forEach(x => {
      const row = el("div", "safe-row", `<span>${esc(x.label || x.value)}</span>`);
      const b = el("button", null, "undo");
      b.onclick = async () => { await post(`/api/allowlist/${x.id}/remove`); loadSafe(); };
      row.appendChild(b); root.appendChild(row);
    });
    root.appendChild(el("h4", null, "Blocked IP addresses"));
    if (!blocks.length) root.appendChild(el("div", "safe-empty", "No IPs blocked from here."));
    blocks.forEach(x => {
      const row = el("div", "safe-row", `<span>${esc(x.ip)}</span>`);
      const b = el("button", null, "unblock");
      b.onclick = async () => {
        const r = await post(`/api/blocks/${encodeURIComponent(x.ip)}/unblock`);
        if (!r.ok) notice("Not unblocked", r.message, "bad", r.manual);
        loadSafe();
      };
      row.appendChild(b); root.appendChild(row);
    });
  }
  safeBtn.addEventListener("click", (e) => { e.stopPropagation(); setDl(false); setSafe(safePop.hidden); });
  safePop.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => setSafe(false));
  loadSafe().catch(() => {});

  // keyboard: M = mute, T = theme (ignore while typing in a field)
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { collapseMascot(); setDl(false); setSafe(false); return; }
    const tag = (e.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === "m" || e.key === "M") toggleMute();
    else if (e.key === "t" || e.key === "T") toggleTheme();
    else if (e.key === "w" || e.key === "W") setWallpaper(!document.body.classList.contains("wall-on"));
  });

  // react to OS theme changes while on "follow OS"
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (!storedTheme()) applyTheme();
    });
  }

  // ---- init --------------------------------------------------------------
  try { muted = localStorage.getItem(LS_MUTED) === "1"; } catch (_) {}
  applyTheme();
  applyMute();
  try { if (localStorage.getItem(LS_WALL) === "1") setWallpaper(true, true); } catch (_) {}
  initMascot();
  refresh();
  setInterval(refresh, POLL_MS);
})();
