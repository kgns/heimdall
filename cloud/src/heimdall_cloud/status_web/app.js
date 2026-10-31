// Incident status page: reads the report for the incident named by the
// share link in the URL and refreshes it while the incident is open.
"use strict";

(() => {
  const OPEN_REFRESH_MS = 3000;
  const CLOSED_REFRESH_MS = 30000;
  const $ = (id) => document.getElementById(id);
  const token = decodeURIComponent(location.pathname.replace(/^\/i\//, "").replace(/\/$/, ""));

  let report = null;
  let timer = null;
  let ticker = null;
  // Who the page speaks to: the ISP (default) or its customer.
  let view = new URLSearchParams(location.search).get("view") === "customer" ? "customer" : "isp";

  const dateFmt = new Intl.DateTimeFormat("en-GB", {
    day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  const timeFmt = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  function duration(s) {
    s = Math.max(0, Math.round(s));
    if (s < 90) return `${s} s`;
    const m = Math.round(s / 60);
    if (m < 90) return `${m} min`;
    const h = Math.floor(s / 3600);
    return `${h} h ${Math.round((s - h * 3600) / 60)} min`;
  }

  function ms(v) {
    if (v === null || v === undefined) return "–";
    return v >= 100 ? `${Math.round(v)} ms` : `${v.toFixed(1)} ms`;
  }

  const SCOPE = {
    client: "One device", home: "Several devices", backhaul: "Mesh extender link",
    access: "ISP access network", service: "One service", dns: "DNS",
  };
  const SEEN_BY = { extender: "the mesh extender", gateway: "the home gateway", cloud: "the cloud probe" };

  function ownerClass(party) {
    if (party === "customer" || party === "equipment") return "customer";
    if (party === "service") return "service";
    if (party.startsWith("isp")) return "isp";
    return "";
  }

  function render(r) {
    report = r;
    const inc = r.incident;
    const v = r.verdict;
    const open = inc.status === "open";
    document.body.classList.toggle("resolved-page", !open);

    const status = $("status");
    status.className = `pill ${open ? "open" : "resolved"}`;
    status.textContent = open ? "Ongoing" : "Resolved";
    $("mode").hidden = inc.mode !== "fast";

    $("headline").textContent = v.headline;
    document.title = `${open ? "Ongoing" : "Resolved"}: ${v.headline} · Heimdall`;
    $("subline").textContent =
      `${SCOPE[inc.scope] || "Incident"} at home ${inc.site} · detected by ${SEEN_BY[inc.seen_by] || inc.device}`;

    const customer = view === "customer";
    $("view-isp").setAttribute("aria-pressed", String(!customer));
    $("view-customer").setAttribute("aria-pressed", String(customer));
    $("owner-h").textContent = customer ? "Whose side it is on" : "Who should act";
    $("fix-h").textContent = customer ? "What you can do" : "Recommended fix";

    const owner = document.querySelector(".owner");
    owner.className = `card owner ${ownerClass(v.party)}`;
    $("party").textContent = customer ? v.customer_label : v.party_label;
    $("isp-note").textContent = customer ? v.customer_note : v.isp_note;
    $("home-link-p").hidden = !customer || !r.home_link;
    if (r.home_link) $("home-link").href = r.home_link;

    $("t-start").textContent = dateFmt.format(inc.started_ms);
    $("t-detect").textContent =
      inc.detected_ms > inc.started_ms
        ? `${timeFmt.format(inc.detected_ms)} (+${duration((inc.detected_ms - inc.started_ms) / 1000)})`
        : timeFmt.format(inc.detected_ms);
    $("t-end-label").textContent = open ? "Status" : "Resolved";
    $("t-end").textContent = open ? "Still going on" : timeFmt.format(inc.ended_ms);
    renderDuration();

    const path = $("path");
    path.replaceChildren(
      ...r.path.map((seg) => {
        const li = el("li", `seg ${seg.state}`, seg.label);
        const note = { fault: "cause", affected: "also degraded", normal: "normal" }[seg.state];
        li.append(el("small", null, note));
        li.setAttribute("aria-label", `${seg.label}: ${note}`);
        return li;
      }),
    );

    $("why").textContent = v.why;
    $("clients").replaceChildren(
      ...r.clients.map((c) => {
        const li = el("li");
        li.append(el("b", null, c.label), el("span", null, c.where || ""));
        return li;
      }),
    );

    const steps = customer ? v.customer_fixes : v.fixes;
    const fixes = steps.length ? steps : ["No specific action yet; keep monitoring."];
    $("fixes").replaceChildren(...fixes.map((f) => el("li", null, f)));

    $("checks").replaceChildren(
      ...r.checks.map((c) => {
        const li = el("li", c.state);
        const ic = el("span", "ic", c.state === "normal" ? "✓" : "!");
        ic.setAttribute("aria-hidden", "true");
        li.append(ic, el("span", null, `${c.label}: ${c.state === "normal" ? "normal" : "also degraded"}`));
        li.append(el("small", null, c.note));
        return li;
      }),
    );

    const meas = $("measurements");
    if (!r.measurements.length) {
      meas.replaceChildren(el("li", "muted", "No measurement details for this incident."));
    } else {
      const top = Math.max(...r.measurements.map((m) => Math.max(m.current_ms || 0, m.baseline_ms || 0)), 1);
      meas.replaceChildren(
        ...r.measurements.map((m) => {
          const li = el("li");
          const row = el("div", "row");
          row.append(el("span", null, m.label), el("span", "val", `${ms(m.current_ms)} vs ${ms(m.baseline_ms)}`));
          li.append(row, el("small", null, `${m.what}: ${open ? "now" : "during the incident"} vs usual`));
          const bars = el("div", "bars");
          bars.setAttribute("aria-hidden", "true");
          const now = el("span", "now");
          const usual = el("span", "usual");
          now.style.width = `${Math.max(1, ((m.current_ms || 0) / top) * 100)}%`;
          usual.style.width = `${Math.max(1, ((m.baseline_ms || 0) / top) * 100)}%`;
          bars.append(now, usual);
          li.append(bars);
          return li;
        }),
      );
    }

    $("foot-id").textContent = `Incident ${inc.id} · ${inc.device}`;
    $("foot-updated").textContent = `Updated ${timeFmt.format(r.updated_ms)}`;

    const live = $("live");
    live.hidden = false;
    live.classList.toggle("on", open);
    $("live-text").textContent = open ? "Live" : "Final";

    $("loading").hidden = true;
    $("error").hidden = true;
    $("report").hidden = false;
  }

  function renderDuration() {
    if (!report) return;
    const inc = report.incident;
    const end = inc.status === "open" ? Date.now() : inc.ended_ms;
    const s = inc.status === "open" || inc.duration_s === null ? (end - inc.started_ms) / 1000 : inc.duration_s;
    $("t-dur").textContent = duration(s);
  }

  function fail(status, message) {
    $("loading").hidden = true;
    $("report").hidden = true;
    $("error").hidden = false;
    $("live").hidden = true;
    $("error-title").textContent = status === 410 ? "This link has expired" : "This link does not work";
    $("error-text").textContent =
      status === 410
        ? "Status links stay valid for 30 days. Ask for a new one."
        : status === 404 && message !== "unknown link"
          ? "This incident is no longer available."
          : message && status === 0
            ? message
            : "Check that the whole link was copied, or ask for a new one.";
  }

  async function load() {
    clearTimeout(timer);
    let next = OPEN_REFRESH_MS;
    try {
      const resp = await fetch(`/api/i/${encodeURIComponent(token)}`, { cache: "no-store" });
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        if (report && resp.status >= 500) {
          $("live-text").textContent = "Reconnecting…";
        } else {
          fail(resp.status, body.error);
          return;
        }
      } else {
        render(body);
        if (body.incident.status !== "open") next = CLOSED_REFRESH_MS;
      }
    } catch {
      if (report) $("live-text").textContent = "Reconnecting…";
      else fail(0, "The report could not be loaded. Check the connection and reload the page.");
      next = OPEN_REFRESH_MS * 2;
    }
    if (!document.hidden) timer = setTimeout(load, next);
  }

  function setView(next) {
    view = next;
    const url = new URL(location.href);
    if (view === "customer") url.searchParams.set("view", "customer");
    else url.searchParams.delete("view");
    history.replaceState(null, "", url);
    if (report) render(report);
  }
  $("view-isp").addEventListener("click", () => setView("isp"));
  $("view-customer").addEventListener("click", () => setView("customer"));

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) load();
    else clearTimeout(timer);
  });

  if (!token) {
    fail(404);
    return;
  }
  ticker = setInterval(renderDuration, 1000);
  load();
  window.addEventListener("pagehide", () => clearInterval(ticker));
})();
