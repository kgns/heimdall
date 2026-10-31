// Home report: a week of one home's network, for the customer.
"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const token = decodeURIComponent(location.pathname.replace(/^\/h\//, "").replace(/\/$/, ""));
  const dayFmt = new Intl.DateTimeFormat("en-GB", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" });
  const whenFmt = new Intl.DateTimeFormat("en-GB", { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const timeFmt = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit" });

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  function duration(s) {
    if (s === null || s === undefined) return "ongoing";
    if (s < 90) return `${Math.round(s)} s`;
    const m = Math.round(s / 60);
    return m < 90 ? `${m} min` : `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
  }

  const TONE = { good: ["Healthy", "resolved"], home: ["Check your home", "open"], isp: ["Provider issues", "open"] };
  const SIDE = { home: "Inside your home", equipment: "Your router or extender", isp: "Your provider", service: "The service" };

  function render(r) {
    const [toneText, toneCls] = TONE[r.tone] || TONE.good;
    const tone = $("tone");
    tone.className = `pill ${toneCls}`;
    tone.textContent = toneText;
    $("headline").textContent = r.headline;
    $("subline").textContent =
      `Home ${r.site} · ${dayFmt.format(Date.parse(r.period.from))} to ${dayFmt.format(Date.parse(r.period.to))}`;
    $("n-home").textContent = r.counts.home + r.counts.equipment;
    $("n-isp").textContent = r.counts.isp + r.counts.service;

    const parts = r.delay.parts;
    if (parts.length) {
      $("delay-total").textContent =
        `A typical connection from your devices to a website took about ${Math.round(r.delay.total_ms)} ms. ` +
        "This is how it adds up:";
      $("budget").replaceChildren(
        ...parts.map((p) => {
          const s = el("span", `part ${p.side}`);
          s.style.flexGrow = String(Math.max(p.ms, r.delay.total_ms * 0.02));
          return s;
        }),
      );
      $("budget-list").replaceChildren(
        ...parts.map((p) => {
          const li = el("li", p.side);
          li.append(el("span", "dot-s"), el("span", null, p.label), el("b", null, `${p.ms} ms`));
          return li;
        }),
      );
    } else {
      $("delay-total").textContent = "Not enough data yet; the first daily analysis runs after a full day.";
    }

    $("days").replaceChildren(
      ...r.days.map((d) => {
        const li = el("li", !d.analysed ? "na" : d.slow_hours ? "slow" : "ok");
        li.append(el("b", null, dayFmt.format(Date.parse(d.date))));
        li.append(
          el("span", null, !d.analysed ? "no data" : d.slow_hours ? `${d.slow_hours} slow hour${d.slow_hours > 1 ? "s" : ""}` : "all good"),
        );
        return li;
      }),
    );

    const incs = $("incidents");
    if (!r.incidents.length) {
      incs.replaceChildren(el("li", "muted", "No problems worth mentioning this week."));
    } else {
      incs.replaceChildren(
        ...r.incidents.map((i) => {
          const li = el("li", i.side);
          const a = el("a", "inc-title", i.headline);
          a.href = i.link;
          const meta = el("span", "muted");
          meta.textContent = `${whenFmt.format(i.started_ms)} · ${i.open ? "still going on" : duration(i.duration_s)}`;
          const chip = el("span", `chip ${i.side}`, SIDE[i.side] || i.customer_label);
          li.append(a, meta, chip);
          if (i.demo) li.append(el("span", "chip demo", "demo"));
          return li;
        }),
      );
    }

    const devs = $("devices");
    if (!r.devices.length) {
      devs.replaceChildren(el("li", "muted", "No device details yet."));
    } else {
      devs.replaceChildren(
        ...r.devices.map((d) => {
          const li = el("li", d.ok ? "ok" : "warn");
          const head = el("div", "dev-head");
          head.append(el("b", null, d.label), el("span", "muted", d.where));
          li.append(head);
          if (d.ok) li.append(el("span", "fine", "Working well"));
          for (const t of d.tips) {
            const p = el("p", "tip");
            p.append(el("span", "issue", t.issue), el("span", "muted", ` · ${t.tip}`));
            li.append(p);
          }
          return li;
        }),
      );
    }

    $("foot-site").textContent = `Home ${r.site}`;
    $("foot-updated").textContent = `Updated ${timeFmt.format(r.updated_ms)}`;
    $("loading").hidden = true;
    $("report").hidden = false;
  }

  function fail(status) {
    $("loading").hidden = true;
    $("error").hidden = false;
    $("error-title").textContent = status === 410 ? "This link has expired" : "This link does not work";
    $("error-text").textContent =
      status === 410 ? "Report links stay valid for 30 days. Ask for a new one." : "Check that the whole link was copied.";
  }

  async function load() {
    try {
      const resp = await fetch(`/api/h/${encodeURIComponent(token)}`, { cache: "no-store" });
      if (!resp.ok) return fail(resp.status);
      render(await resp.json());
    } catch {
      fail(0);
    }
  }

  if (!token) fail(404);
  else load();
})();
