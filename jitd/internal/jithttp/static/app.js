// jitd web UI: pages are server-rendered; this sends mutations to /v1/*,
// runs the request picker and the flow form's rows, copies text, and reloads
// pages when something changed on the server.
"use strict";

function flash(msg, ok) {
  const el = document.getElementById("flash");
  el.textContent = msg;
  el.className = ok ? "flash ok" : "flash error";
  el.hidden = false;
  window.scrollTo(0, 0);
}

// acting is true while a button's own call is on its way, so that the live
// reload does not show the half-way state of it.
let acting = false;

async function api(method, url, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(url, opts);
  let data = null;
  const text = await resp.text();
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = { error: { message: text } }; }
  if (!resp.ok) {
    const e = (data && data.error) || {};
    const err = new Error((e.code ? e.code + ": " : "") + (e.message || resp.statusText));
    err.data = data;
    throw err;
  }
  return data;
}

const list = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);

// resources reads the flow form's "Gives access to" rows; rows without a
// target are ignored.
const resources = (f) => [...f.querySelectorAll(".resrow")].map((row) => ({
  name: row.querySelector('[name="res_name"]').value.trim(),
  description: row.querySelector('[name="res_desc"]').value.trim(),
})).filter((r) => r.name);

// Add / remove rows.
document.addEventListener("click", (ev) => {
  const add = ev.target.closest("#addres");
  const rm = ev.target.closest("[data-removeres]");
  if (add) {
    const rows = document.getElementById("resrows");
    const row = rows.querySelector(".resrow").cloneNode(true);
    for (const i of row.querySelectorAll("input")) i.value = "";
    rows.appendChild(row);
    row.querySelector("input").focus();
  } else if (rm) {
    const rows = document.getElementById("resrows");
    const row = rm.closest(".resrow");
    if (rows.querySelectorAll(".resrow").length > 1) row.remove();
    else for (const i of row.querySelectorAll("input")) i.value = "";
  }
});

// dur reads an amount + unit pair into an API duration such as "3d".
const dur = (f, name) => {
  const box = f.querySelector('[data-dur="' + name + '"]');
  return box.querySelector("input").value.trim() + box.querySelector("select").value;
};

// Flow form, "What an approval grants": each thing an approval can do
// (Tailscale access, Okta groups, Google groups) is a section that shows
// once it is added. One that is not added saves as empty.
const granted = (f, kind) => {
  const s = f.querySelector('[data-action="' + kind + '"]');
  return !!s && !s.hidden;
};

function syncGrants(box) {
  const sections = [...box.querySelectorAll("[data-action]")];
  const on = sections.filter((s) => !s.hidden).map((s) => s.dataset.action);
  // A field in a section that is not added must not hold up Save.
  for (const s of sections) for (const i of s.querySelectorAll("input")) i.disabled = s.hidden;
  for (const b of box.querySelectorAll("[data-add]")) b.hidden = on.includes(b.dataset.add);
  box.classList.toggle("empty", on.length === 0);
  // Where only one thing can be granted there is nothing to swap it for.
  for (const s of sections) s.querySelector("[data-removeaction]").hidden = sections.length < 2;
  const picks = box.querySelector("[data-picks]");
  picks.hidden = on.length > 0 && !picks.querySelector(".pick:not([hidden])");
}

for (const box of document.querySelectorAll("[data-grants]")) syncGrants(box);

document.addEventListener("click", (ev) => {
  const add = ev.target.closest("[data-add]");
  const rm = ev.target.closest("[data-removeaction]");
  if (!add && !rm) return;
  const box = (add || rm).closest("[data-grants]");
  if (add) {
    const s = box.querySelector('[data-action="' + add.dataset.add + '"]');
    // Newest last, just above the "Add another" row.
    box.insertBefore(s, box.querySelector("[data-picks]"));
    s.hidden = false;
    syncGrants(box);
    s.querySelector("input").focus();
  } else {
    const s = rm.closest("[data-action]");
    s.hidden = true;
    syncGrants(box);
  }
});

function workflowBody(f) {
  if (f.querySelector("[data-grants]") && !["tailscale", "okta", "google"].some((k) => granted(f, k))) {
    throw new Error("Pick what an approval grants: Tailscale access, Okta groups or Google groups.");
  }
  return {
    name: f.name.value,
    description: f.description.value,
    grants: grantsBody(f),
    resources: resources(f),
    requesters: list(f.requesters.value),
    approvers: list(f.approvers.value),
    allow_self_approval: f.allow_self_approval.checked,
    auto_approve: f.auto_approve.checked,
    max_duration: dur(f, "max_duration"),
    default_duration: dur(f, "default_duration"),
    approval_timeout: dur(f, "approval_timeout"),
    approvals_required: Number(f.approvals_required.value),
    disabled: !f.enabled.checked,
    slack: slackBody(f),
  };
}

// grantsBody reads "What an approval grants": one key per kind that was
// added, as the API takes it.
function grantsBody(f) {
  const g = {};
  if (granted(f, "tailscale")) g.tailscale = { attribute: f.attribute.value.trim() };
  for (const [kind, label] of [["okta", "Okta"], ["google", "Google"]]) {
    if (!granted(f, kind)) continue;
    const groups = list(f[kind + "_groups"].value).map((name) => ({ name }));
    if (!groups.length) throw new Error("Name at least one " + label + " group, or remove " + label + " groups.");
    g[kind] = { groups };
  }
  return g;
}

// slackBody reads the flow form's Slack part (absent in builds without it).
function slackBody(f) {
  const ch = f.slack_channel;
  if (!ch) return undefined;
  const opt = ch.selectedOptions[0];
  return {
    channel: ch.value,
    channel_name: (opt && opt.dataset.name) || "",
    dm_approvers: f.slack_dm.checked,
    browser_only: f.slack_browser_only.checked,
  };
}

document.addEventListener("submit", async (ev) => {
  const f = ev.target;
  if (!f.dataset.form) return;
  ev.preventDefault();
  try {
    if (f.dataset.form === "workflow") {
      const id = f.dataset.id;
      await api(id ? "PUT" : "POST", id ? "/v1/workflows/" + id : "/v1/workflows", workflowBody(f));
      location.href = "/admin/workflows";
    } else if (f.dataset.form === "request") {
      await submitRequests(f);
    } else if (f.dataset.form === "slack-connect") {
      await api("POST", "/v1/slack/connect", {
        bot_token: f.bot_token.value.trim(), app_token: f.app_token.value.trim(), allowed_domains: list(f.allowed_domains.value),
      });
      location.reload();
    } else if (f.dataset.form === "slack-domains") {
      await api("PUT", "/v1/slack/domains", { allowed_domains: list(f.allowed_domains.value) });
      flash("Saved.", true);
    } else if (f.dataset.form === "slack-test") {
      await api("POST", "/v1/slack/test", { channel: f.channel.value });
      flash("Sent. Have a look in Slack.", true);
    } else if (f.dataset.form === "okta-save") {
      await credSave(f, "/v1/okta", "Signing in to Okta…");
    } else if (f.dataset.form === "ts-save") {
      await credSave(f, "/v1/setup/credentials", "Trying it against Tailscale…");
    } else if (f.dataset.form === "okta-check") {
      await oktaGroup(f);
    } else if (f.dataset.form === "google-save") {
      await credSave(f, "/v1/google", "Signing in to Google…");
    } else if (f.dataset.form === "google-limits") {
      await credSave(f, "/v1/google", "Saving…");
    } else if (f.dataset.form === "google-check") {
      await googleGroup(f);
    }
  } catch (e) {
    flash(e.message);
  }
});

document.addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-action], button[data-delete]");
  if (!b) return;
  ev.preventDefault();
  b.disabled = true;
  try {
    if (b.dataset.delete) {
      if (b.dataset.armed !== "1") {
        // Two-step confirm without a dialog.
        b.dataset.armed = "1";
        b.textContent = "Click again to delete";
        b.disabled = false;
        return;
      }
      await api("DELETE", b.dataset.delete);
      location.href = b.dataset.then || "/";
    } else {
      const noteEl = document.getElementById("note");
      let note = noteEl ? noteEl.value.trim() : "";
      if (b.dataset.needsNote && !note) {
        // Declining needs a reason; ask for it inline when there is no note field.
        if (noteEl) { flash(b.dataset.needsNote); noteEl.focus(); b.disabled = false; return; }
        note = (window.prompt(b.dataset.needsNote) || "").trim();
        if (!note) { b.disabled = false; return; }
      }
      acting = true;
      await api("POST", b.dataset.action, { note });
      location.reload();
    }
  } catch (e) {
    acting = false;
    flash(e.message);
    // Failed approvals are still recorded; show the updated timeline.
    if (e.data && e.data.request) setTimeout(() => location.reload(), 2500);
    b.disabled = false;
  }
});

// Request picker: filter, tiles/list view, multi-select, then a modal asks
// for duration and reason and files one request per chosen flow.
(function () {
  const picker = document.getElementById("picker");
  if (!picker) return;
  const flows = document.getElementById("flows");
  const boxes = () => [...flows.querySelectorAll('input[name="workflow"]')];
  const chosen = () => boxes().filter((b) => b.checked);
  const dialog = document.getElementById("reqdialog");
  const form = dialog.querySelector("form");

  // View toggle, remembered per browser.
  const setView = (v) => {
    flows.classList.toggle("list", v === "list");
    for (const b of picker.querySelectorAll(".views button")) b.classList.toggle("on", b.dataset.view === v);
    try { localStorage.setItem("jit.view", v); } catch (e) { /* private mode */ }
  };
  picker.addEventListener("click", (ev) => {
    const b = ev.target.closest(".views button");
    if (b) setView(b.dataset.view);
  });
  let saved = "tiles";
  try { saved = localStorage.getItem("jit.view") || "tiles"; } catch (e) { /* ignore */ }
  setView(saved);

  // Filter: hide tiles whose text does not contain every word typed.
  const filter = document.getElementById("filter");
  const applyFilter = () => {
    const words = filter.value.toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    for (const t of flows.querySelectorAll(".tile")) {
      const text = t.dataset.text.toLowerCase();
      const hit = words.every((w) => text.includes(w));
      t.hidden = !hit;
      if (hit) shown++;
    }
    document.getElementById("nomatch").hidden = shown > 0;
  };
  filter.addEventListener("input", applyFilter);
  filter.focus();

  // Selection bar.
  const selbar = document.getElementById("selbar");
  const updateBar = () => {
    const n = chosen().length;
    selbar.hidden = n === 0;
    document.getElementById("selcount").textContent = n === 1 ? "1 selected" : n + " selected";
    document.getElementById("openreq").textContent = n > 1 ? "Request access (" + n + ")" : "Request access";
  };
  flows.addEventListener("change", (ev) => { if (ev.target.name === "workflow") updateBar(); });
  document.getElementById("clearsel").addEventListener("click", () => { for (const b of boxes()) b.checked = false; updateBar(); });
  updateBar();

  // Modal: duration is an amount and a unit (minutes, hours, days). Only
  // units that fit under the tightest maximum of the chosen flows are
  // offered; it starts at the shortest of their defaults, in its largest
  // whole unit (2 hours, not 120 minutes).
  const human = (b) => b.dataset.maxlabel;
  let maxSecs = Infinity, maxNote = "";
  const durSecs = () => Number(form.dur_n.value) * Number(form.dur_unit.value);
  const checkDur = () => {
    const n = Number(form.dur_n.value), s = durSecs();
    const hint = document.getElementById("maxhint");
    let bad = "";
    if (!Number.isInteger(n) || n < 1) bad = "Enter a whole number of at least 1.";
    else if (s > maxSecs) bad = "That is more than allowed. " + maxNote;
    hint.textContent = bad || maxNote;
    hint.classList.toggle("bad", !!bad);
    document.getElementById("submitreq").disabled = !!bad;
    return !bad;
  };
  form.dur_n.addEventListener("input", checkDur);
  form.dur_unit.addEventListener("change", checkDur);
  const openModal = () => {
    const sel = chosen();
    if (!sel.length) return;
    const ul = document.getElementById("chosen");
    ul.innerHTML = "";
    let max = Infinity, tightest = null, def = Infinity;
    for (const b of sel) {
      const li = document.createElement("li");
      li.innerHTML = "<span></span><small></small>";
      li.firstChild.textContent = b.dataset.name;
      li.lastChild.textContent = "up to " + human(b) + (b.dataset.active ? " · you already have a " + (b.dataset.active === "approved" ? "live" : b.dataset.active) + " request" : "");
      ul.appendChild(li);
      if (Number(b.dataset.max) < max) { max = Number(b.dataset.max); tightest = b; }
      if (Number(b.dataset.default) > 0 && Number(b.dataset.default) < def) def = Number(b.dataset.default);
    }
    maxSecs = max;
    maxNote = sel.length > 1
      ? "Up to " + human(tightest) + " (the limit of " + tightest.dataset.name + ")."
      : "Up to " + human(tightest) + ".";
    if (!(def <= max)) def = Math.min(3600, max);
    let unit = null;
    for (const o of form.dur_unit.options) {
      o.hidden = o.disabled = Number(o.value) > max;
      if (!o.disabled && def % Number(o.value) === 0) unit = o; // largest whole unit wins
    }
    unit = unit || form.dur_unit.options[0];
    unit.selected = true;
    form.dur_n.value = Math.max(1, Math.round(def / Number(unit.value)));
    document.getElementById("submitreq").textContent = sel.length > 1 ? "Submit " + sel.length + " requests" : "Submit request";
    checkDur();
    const res = document.getElementById("results");
    res.hidden = true; res.innerHTML = "";
    dialog.showModal();
    form.reason.focus();
  };
  document.getElementById("openreq").addEventListener("click", openModal);
  document.getElementById("closereq").addEventListener("click", () => dialog.close());
  // Enter in the filter with one match selects it; Escape closes the modal (native).
  filter.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const visible = boxes().filter((b) => !b.closest(".tile").hidden);
    if (visible.length === 1) { visible[0].checked = true; updateBar(); }
  });

  // Submit one request per chosen flow; report each; leave when all went in.
  // When: now, or a local date and time up to 30 days ahead.
  const startInput = form.start_at;
  const pad = (n) => String(n).padStart(2, "0");
  const local = (d) => d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes());
  form.querySelectorAll('input[name="when"]').forEach((r) => r.addEventListener("change", () => {
    const later = form.when.value === "later";
    startInput.disabled = !later;
    startInput.required = later;
    if (later) {
      const now = new Date();
      startInput.min = local(new Date(now.getTime() + 5 * 60000));
      startInput.max = local(new Date(now.getTime() + 30 * 86400000));
      if (!startInput.value) {
        const t = new Date(now.getTime() + 3600000);
        t.setMinutes(0, 0, 0);
        startInput.value = local(t);
      }
      startInput.focus();
    }
  }));
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  if (tz) document.getElementById("whenhint").textContent += " Times are in " + tz + ".";
  const startAt = () => (form.when.value === "later" && startInput.value) ? new Date(startInput.value).toISOString() : undefined;

  window.submitRequests = async (f) => {
    if (!checkDur()) return;
    if (f.when.value === "later" && !startInput.reportValidity()) return;
    const sel = chosen();
    const btn = document.getElementById("submitreq");
    btn.disabled = true;
    const res = document.getElementById("results");
    res.hidden = false; res.innerHTML = "";
    let failed = 0;
    for (const b of sel) {
      if (b.dataset.done) continue; // filed on an earlier try
      const li = document.createElement("li");
      res.appendChild(li);
      try {
        const duration = f.dur_n.value + f.dur_unit.selectedOptions[0].dataset.suffix;
        const r = await api("POST", "/v1/requests", { workflow_id: b.value, duration, reason: f.reason.value, start_at: startAt() });
        b.dataset.done = r.id;
        li.className = "ok";
        li.textContent = b.dataset.name + (r.start_at ? ": requested, starting " + new Date(r.start_at).toLocaleString() : ": requested");
      } catch (e) {
        failed++;
        li.className = "bad";
        const rid = e.data && e.data.error && e.data.error.request_id;
        li.textContent = b.dataset.name + ": " + (rid ? "you already have a request for this " : e.message);
        if (rid) {
          const a = document.createElement("a");
          a.href = "/requests/" + rid; a.textContent = "(open it)";
          li.appendChild(a);
        }
      }
    }
    const all = sel.map((b) => b.dataset.done).filter(Boolean);
    if (failed === 0) {
      location.href = all.length === 1 ? "/requests/" + all[0] : "/requests?scope=mine";
      return;
    }
    if (all.length) {
      const li = document.createElement("li");
      li.textContent = all.length + " filed. ";
      const a = document.createElement("a");
      a.href = "/requests?scope=mine"; a.textContent = "See my requests";
      li.appendChild(a);
      res.appendChild(li);
    }
    btn.disabled = false;
    btn.textContent = all.length ? "Retry the rest" : "Try again";
    if (all.length) {
      const c = document.getElementById("closereq");
      c.textContent = "Done";
      c.onclick = () => { location.href = "/requests?scope=mine"; };
    }
  };
})();

// Whole table rows open their page; copy buttons copy an element's text.
document.addEventListener("click", (ev) => {
  const c = ev.target.closest("[data-copy]");
  if (c) {
    // navigator.clipboard only exists on HTTPS (and localhost), and may be
    // refused; plain http://jit needs the older select-and-copy route.
    const text = document.getElementById(c.dataset.copy).textContent;
    const done = (ok) => {
      c.textContent = ok ? "Copied" : "Select and copy it yourself";
      setTimeout(() => (c.textContent = "Copy"), 2000);
    };
    const legacy = () => {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      ta.remove();
      return ok;
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => done(true), () => done(legacy()));
    } else {
      done(legacy());
    }
    return;
  }
  if (ev.target.closest("a, button, input, select, textarea")) return;
  const tr = ev.target.closest("tr[data-href]");
  if (tr) location.href = tr.dataset.href;
});

// Live pages: reload when something changed on the server (a decision, a new
// request, an expiry). Only while the tab is visible and nobody is typing.
(function () {
  const main = document.querySelector("main[data-changes]");
  const path = location.pathname;
  const live = path === "/" || path === "/admin" || path === "/requests" || path === "/admin/requests" || /^\/requests\/req_/.test(path);
  if (!main || !live) return;
  let seen = main.dataset.changes;
  setInterval(async () => {
    if (document.hidden || acting) return;
    const note = document.getElementById("note");
    if (note && note.value) return;
    try {
      const r = await fetch("/v1/changes", { cache: "no-store" });
      const d = await r.json();
      if (String(d.changes) !== seen) location.reload();
    } catch (e) { /* server away; try again next tick */ }
  }, 5000);
})();

// Setup page: re-run the check, then show the fresh result.
(() => {
  const b = document.getElementById("setupcheck");
  if (!b) return;
  b.addEventListener("click", async () => {
    b.disabled = true;
    b.textContent = "Checking…";
    try {
      await api("POST", "/v1/setup/check");
      location.reload();
    } catch (e) {
      flash(e.message);
      b.disabled = false;
      b.textContent = "Check again";
    }
  });
})();

// Okta, Google and Tailscale pages: try the credentials and save them.
// What went wrong stays in the form, next to what has to be fixed. A
// disabled field is one jitd's environment sets: it is not sent.
async function credSave(f, path, busy) {
  const body = {};
  for (const el of f.querySelectorAll("input[name], textarea[name]")) if (!el.disabled) body[el.name] = el.value.trim();
  const err = f.querySelector(".formerr"), b = f.querySelector("button[type=submit]"), label = b.textContent;
  err.hidden = true;
  b.disabled = true;
  b.textContent = busy;
  try {
    await api("PUT", path + (f.dataset.force === "1" ? "?force=1" : ""), body);
    location.reload();
  } catch (e) {
    const said = (e.data && e.data.error) || {};
    err.textContent = said.message || e.message;
    err.hidden = false;
    b.disabled = false;
    b.textContent = label;
    if (said.force === "1" && f.dataset.force !== "1") {
      // jitd said what saving this costs (memberships it holds stay
      // behind). A second click saves anyway; changing the form starts over.
      f.dataset.force = "1";
      b.textContent = "Save anyway";
      f.addEventListener("input", () => {
        delete f.dataset.force;
        b.textContent = label;
      }, { once: true });
    }
  }
}

// groupCheck asks jitd about one group and lists what tell(group, line)
// makes of the answer.
async function groupCheck(f, kind, tell) {
  const out = document.getElementById(kind + "check-result");
  const line = (ok, text) => {
    const li = document.createElement("li");
    li.className = ok ? "ok" : "bad";
    li.textContent = text;
    out.append(li);
  };
  out.replaceChildren();
  out.hidden = false;
  try {
    tell((await api("POST", "/v1/" + kind + "/check", { group: f.group.value.trim() })).group, line);
  } catch (e) {
    line(false, (e.data && e.data.error && e.data.error.message) || e.message);
  }
}

// Okta page: what jitd can tell about one group.
function oktaGroup(f) {
  return groupCheck(f, "okta", (g, line) => {
    line(true, "Found " + g.name + " (" + g.id + ").");
    if (g.manageable) line(true, "Okta manages its members itself, so they can be changed through the API.");
    else line(false, "It is a " + g.type + " group: its members come from a directory, an app or a rule, so Okta does not let jitd change them. A flow cannot grant it.");
    if (g.grant_allowed) line(true, "It is on the grant allowlist: a flow may grant it.");
    else line(false, "It is not on the grant allowlist (OKTA_GRANT_ALLOWLIST): a flow may not grant it.");
    if (g.read_allowed) line(true, "It is on the read allowlist: a flow may name okta:" + g.name + " as requesters or approvers.");
    else line(false, "It is not on the read allowlist (OKTA_READ_ALLOWLIST): it cannot be used as an okta: requester or approver.");
    if (g.members_error) line(false, "jitd cannot list its members: " + g.members_error);
    else line(true, "jitd can list its members: " + g.members + (g.members_capped ? " or more." : "."));
  });
}

// Google page: what jitd can tell about one group.
function googleGroup(f) {
  return groupCheck(f, "google", (g, line) => {
    line(true, "Found " + g.email + (g.name && g.name !== g.email ? " (" + g.name + ")." : "."));
    if (g.manageable) line(true, "Its members are added by hand, so jitd can add and remove them.");
    else line(false, "It is a dynamic group: its members come from a query, so Google does not let jitd change them. A flow cannot grant it.");
    if (g.grant_allowed) line(true, "It is among the groups a flow may grant.");
    else line(false, "It is not among the groups a flow may grant, as set on this page.");
  });
}

// Google page: choosing the key file fills the box, and the box says
// which service account the key is for, before anything is sent.
for (const f of document.querySelectorAll('form[data-form="google-save"]')) {
  const box = f.querySelector("textarea[name=key]"), who = f.querySelector("[data-keyaccount]"), file = f.querySelector("[data-keyfile]");
  const show = () => {
    let email = "";
    try { email = JSON.parse(box.value).client_email || ""; } catch (e) { /* not a key yet */ }
    who.textContent = email ? "This key is for " + email + ": the address that needs the Groups Admin role." : "";
  };
  box.addEventListener("input", show);
  if (file) file.addEventListener("change", async () => {
    if (!file.files[0]) return;
    box.value = await file.files[0].text();
    show();
  });
}

// Okta and Google pages: try the credentials again, and remove them with
// a second click to confirm.
for (const kind of ["okta", "google"]) (() => {
  const check = document.getElementById(kind + "check");
  if (check) check.addEventListener("click", async () => {
    check.disabled = true;
    check.textContent = "Checking…";
    try {
      await api("POST", "/v1/" + kind + "/check", {});
      location.reload();
    } catch (e) {
      flash(e.message);
      check.disabled = false;
      check.textContent = "Check again";
    }
  });
  const b = document.getElementById(kind + "remove");
  if (!b) return;
  b.addEventListener("click", async () => {
    if (b.dataset.armed !== "1") {
      b.dataset.armed = "1";
      b.textContent = "Click again to remove";
      const warn = document.getElementById(kind + "remove-warn");
      if (warn) warn.hidden = false;
      return;
    }
    b.disabled = true;
    try {
      // force: the page said how many memberships jitd still looks after.
      await api("DELETE", "/v1/" + kind + (Number(b.dataset.held) > 0 ? "?force=1" : ""));
      location.reload();
    } catch (e) {
      flash(e.message);
      b.disabled = false;
    }
  });
})();

// Tailscale page: forget the saved credential, with a second click.
(() => {
  const b = document.getElementById("tsremove");
  if (!b) return;
  b.addEventListener("click", async () => {
    if (b.dataset.armed !== "1") {
      b.dataset.armed = "1";
      b.textContent = "Click again to remove";
      const warn = document.getElementById("tsremove-warn");
      if (warn) warn.hidden = false;
      return;
    }
    b.disabled = true;
    try {
      await api("DELETE", "/v1/setup/credentials");
      location.reload();
    } catch (e) {
      flash(e.message);
      b.disabled = false;
    }
  });
})();

// Slack page: disconnect, with a second click to confirm.
(() => {
  const b = document.getElementById("slackdisconnect");
  if (!b) return;
  b.addEventListener("click", async () => {
    if (b.dataset.armed !== "1") {
      b.dataset.armed = "1";
      b.textContent = "Click again to disconnect";
      return;
    }
    b.disabled = true;
    try {
      await api("POST", "/v1/slack/disconnect");
      location.reload();
    } catch (e) {
      flash(e.message);
      b.disabled = false;
    }
  });
})();
