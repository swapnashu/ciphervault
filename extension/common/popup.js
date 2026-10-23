/**
 * CipherVault popup — sign in, fill from the vault, save new logins,
 * and add/edit/delete vault entries (v1.1).
 */

const $ = (id) => document.getElementById(id);
const SCREENS = ["screen-login", "screen-entries", "screen-editor", "screen-viewer", "screen-save"];

const msg = async (m) => chrome.runtime.sendMessage(m) || {};

let tabInfo = null;
let editorState = null;   // {entry | null, mode: 'new'|'edit'}
let viewerState = null;   // entry object
let vaultTab = "site";    // 'site' | 'vault'
let totpTimer = null;

function show(...ids) {
  for (const s of SCREENS) $(s).hidden = !ids.includes(s);
  stopTotpLoop();
}

function stopTotpLoop() {
  if (totpTimer) { clearInterval(totpTimer); totpTimer = null; }
}

function hint(text) {
  $("state-hint").textContent = text || "";
}

const TYPE_ICONS = { LOGIN: "🔑", NOTE: "📝", CARD: "💳", IDENTITY: "🪪", TOTP: "🔢" };

function setFoot(text) {
  $("foot-rev").textContent = text;
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || {};
}

function hostOf(value) {
  try { return new URL(value).host || ""; } catch { return ""; }
}

/* ---------- entry list ---------- */

function entryRow({ icon, title = "", sub = "", tail = () => {}, onClick }) {
  const row = document.createElement("button");
  row.className = "buttonish";
  const who = document.createElement("div");
  who.className = "who";
  const t = document.createElement("span");
  t.className = "tt";
  t.textContent = title;
  who.append(t);
  if (sub) {
    const s = document.createElement("span");
    s.className = "sub";
    s.textContent = sub;
    who.append(s);
  }
  const ico = document.createElement("span");
  ico.className = "icon-tiny";
  ico.textContent = icon;
  row.append(ico, who);
  const tailNode = document.createElement("div");
  tailNode.className = "tail";
  tail(tailNode, row);
  row.append(tailNode);
  row.addEventListener("click", onClick);
  return row;
}

function renderSiteList(data) {
  lastLists.site = data;
  const list = $("site-list");
  list.textContent = "";
  const matched = (data.matched || []).filter(matchesSearch);
  if (!matched.length) {
    $("entries-none").hidden = false;
    $("entries-none").textContent = searchQuery
      ? "Nothing matches this filter."
      : data.total
        ? "No logins match this site (" + data.total + " stored overall)."
        : "No logins stored yet. Save one from a login form, or add one with ✚.";
    return;
  }
  $("entries-none").hidden = true;
  for (const entry of matched) {
    const row = entryRow({
      icon: "🔑",
      title: entry.title || "",
      sub: entry.username || "",
      onClick: () => openViewer(entry.id),
      tail: (tail, row) => {
        const fill = document.createElement("button");
        fill.textContent = "Fill";
        fill.style.cssText = "flex:none;background:#0B6B47;color:#fff;border:0;border-radius:8px;padding:6px 12px;cursor:pointer;";
        fill.addEventListener("click", async (ev) => {
          ev.stopPropagation();
          let totp = null;
          if ((entry.totpSecret || "").trim()) {
            try {
              totp = await cvTotp(
                cvBase32Decode(entry.totpSecret), Math.floor(Date.now() / 1000),
                entry.totpDigits, entry.totpPeriodSeconds, entry.totpAlgorithm,
              );
            } catch { totp = null; }
          }
          try {
            await chrome.tabs.sendMessage(tabInfo.id, {
              cmd: "cvFill",
              username: entry.username,
              password: entry.password,
              totp,
            });
            window.close();
          } catch {
            row.querySelector(".tt").textContent = (entry.title || "") + " (reload the page)";
          }
        });
        tail.append(fill);
      },
    });
    // live TOTP chip beside Fill — the entries payload already carries the seed
    const seed = (entry.totpSecret || "").trim();
    if (seed) {
      const tl = row.querySelector(".tail");
      if (tl) tl.insertBefore(totpChip(entry, seed), tl.firstChild);
    }
    list.append(row);
  }
}

function totpChip(entry, secretFull) {
  const chip = document.createElement("span");
  chip.className = "totp-chip";
  const key = cvBase32Decode(secretFull);
  const tick = () => {
    const nowSec = Math.floor(Date.now() / 1000);
    cvTotp(key, nowSec, entry.totpDigits, entry.totpPeriodSeconds, entry.totpAlgorithm)
      .then((code) => {
        chip.textContent = code;
        chip.classList.toggle("stale", cvTotpRemaining(nowSec, entry.totpPeriodSeconds ?? 30) <= 5);
      })
      .catch(() => { chip.textContent = "----"; });
  };
  tick();
  if (!totpTimer) totpTimer = setInterval(tick, 1000);
  return chip;
}

function renderVaultList(data) {
  lastLists.vault = data;
  const list = $("vault-list");
  list.textContent = "";
  const entries = (data.entries || []).filter(matchesSearch);
  if (!entries.length) {
    $("entries-none").hidden = false;
    $("entries-none").textContent = searchQuery
      ? "Nothing matches this filter."
      : "Vault is empty. Add one with ✚.";
    return;
  }
  $("entries-none").hidden = true;
  entries.sort((a, b) =>
    (b.favorite || 0) - (a.favorite || 0) || String(a.title).localeCompare(String(b.title)));
  for (const e of entries) {
    const row = entryRow({
      icon: TYPE_ICONS[e.type] || "🔑",
      title: (e.favorite ? "★ " : "") + (e.title || "(untitled)"),
      sub: (e.type === "LOGIN" && e.username) ? e.username : "",
      onClick: () => openViewer(e.id),
    });
    list.append(row);
    if (e.hasTotp) fetchSecretsAndChip(row, e); // chip needs the secret
  }
}

async function fetchSecretsAndChip(row, e) {
  const got = await msg({ cmd: "getEntry", id: e.id });
  if (!got || !got.ok || !(got.entry.totpSecret || "").trim() || !row) return;
  const tail = row.querySelector(".tail");
  if (!tail) return;
  tail.textContent = "";
  tail.append(totpChip(got.entry, got.entry.totpSecret || ""));
}

/* ---------- viewer ---------- */

function copyRow({ label, value, masked = false }) {
  const row = document.createElement("button");
  row.className = "copy-row";
  const small = document.createElement("small");
  small.textContent = label;
  const val = document.createElement("div");
  val.className = "val";
  if (masked) {
    const maskedSpan = document.createElement("span");
    maskedSpan.className = "val-masked";
    maskedSpan.textContent = "•".repeat(Math.max(8, (value || "").length));
    const realSpan = document.createElement("span");
    realSpan.style.display = "none";
    realSpan.textContent = value || "";
    row.addEventListener("click", () => {
      row.classList.add("revealed");
      val.textContent = value || "";
      navigator.clipboard.writeText(value || "").catch?.(() => {});
      row.classList.add("copied");
      setTimeout(() => row.classList.remove("copied"), 900);
    });
    val.append(maskedSpan);
  } else {
    val.textContent = value || "";
    row.addEventListener("click", () => {
      navigator.clipboard.writeText(value || "").catch?.(() => {});
      row.classList.add("copied");
      setTimeout(() => row.classList.remove("copied"), 900);
    });
  }
  row.append(small, val);
  if (masked) {
    row.title = "Click to reveal + copy";
  }
  return row;
}

async function openViewer(id) {
  const got = await msg({ cmd: "getEntry", id });
  if (!got || !got.ok || !got.entry) { alert(got && got.error ? got.error : "Entry not found"); return; }
  viewerState = got;
  await renderViewer();
  show("screen-viewer");
}

function liveTotpWidget(parent, entry, secret) {
  const wrap = document.createElement("div");
  wrap.className = "totp-live";
  const code = document.createElement("div");
  code.className = "code";
  const ringWrap = document.createElement("div");
  ringWrap.className = "ring";
  const ring = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  ring.setAttribute("viewBox", "0 0 36 36");
  const bg = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  bg.setAttribute("cx", "18"); bg.setAttribute("cy", "18"); bg.setAttribute("r", "15.9");
  bg.setAttribute("fill", "none"); bg.setAttribute("stroke", "#E3EBE7"); bg.setAttribute("stroke-width", "3.8");
  const arc = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  arc.setAttribute("cx", "18"); arc.setAttribute("cy", "18"); arc.setAttribute("r", "15.9");
  arc.setAttribute("fill", "none"); arc.setAttribute("stroke", "#0B6B47"); arc.setAttribute("stroke-width", "3.8");
  arc.setAttribute("stroke-dasharray", "100 100");
  arc.setAttribute("transform", "rotate(-90 18 18)");
  ring.append(bg, arc);
  ringWrap.append(ring);
  const meta = document.createElement("div");
  meta.className = "meta";
  wrap.append(code, meta, ringWrap);
  parent.append(wrap);
  let chip = wrap.querySelector(".code");
  const key = cvBase32Decode(secret);
  const tick = async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    try {
      chip.textContent = await cvTotp(key, nowSec, entry.totpDigits, entry.totpPeriodSeconds, entry.totpAlgorithm);
      const rem = cvTotpRemaining(nowSec, entry.totpPeriodSeconds || 30);
      const frac = rem / Math.max(1, entry.totpPeriodSeconds || 30);
      const C = 2 * Math.PI * 15.9;
      arc.setAttribute("stroke-dasharray", (C * frac).toFixed(1) + " " + C.toFixed(1));
      chip.classList.toggle("stale", rem <= 5);
      code.classList.toggle("stale", rem <= 5);
      meta.textContent = "code dies in " + rem + "s";
    } catch {
      chip.textContent = "----";
    }
  };
  tick();
  if (!totpTimer) totpTimer = setInterval(tick, 500);
}

async function renderViewer() {
  stopTotpLoop();
  const { entry } = viewerState;
  const body = $("viewer-body");
  body.textContent = "";

  const head = document.createElement("div");
  head.className = "who";
  head.style.cssText = "margin:2px 0 10px";
  const h = document.createElement("b");
  h.textContent = (TYPE_ICONS[entry.type] || "🔑") + " " + (entry.title || "(untitled)");
  h.style.display = "block";
  h.style.fontSize = "15px";
  head.append(h);
  body.append(head);

  if ((entry.type === "LOGIN" || entry.type === "TOTP") && entry.totpSecret) {
    liveTotpWidget(body, entry, entry.totpSecret);
  }
  if (entry.type !== "TOTP" || entry.title) {
    /* title row stays as heading */
  }
  if (entry.username) body.append(copyRow({ label: "Username", value: entry.username }));
  if (entry.password) body.append(copyRow({ label: "Password", value: entry.password, masked: true }));
  if (entry.url) body.append(copyRow({ label: "URL", value: entry.url }));
  if (entry.notes) body.append(copyRow({ label: "Notes", value: entry.notes }));
  for (const f of entry.customFields || []) {
    body.append(copyRow({ label: f.label || "Custom field" + (f.hidden ? " (hidden)" : ""), value: f.value, masked: !!f.hidden }));
  }
  if (!entry.username && !entry.password && !entry.url && !entry.notes &&
      !(entry.customFields || []).length) {
    const p = document.createElement("p");
    p.className = "hint";
    p.textContent = "No fields stored on this entry.";
    body.append(p);
  }
  $("btn-view-edit").hidden = false;
  $("btn-view-delete").hidden = false;
}

$("btn-view-back").addEventListener("click", () => renderTab());
$("btn-view-edit").addEventListener("click", () => openEditor(viewerState.entry));
$("btn-view-delete").addEventListener("click", async () => {
  if (!confirm("Delete “" + (viewerState.entry.title || "this entry") + "” from the vault?")) return;
  const r = await msg({ cmd: "deleteEntry", id: viewerState.entry.id });
  if (r && r.ok) return renderTab();
  alert(r && r.error ? r.error : "Delete failed");
});

/* ---------- editor ---------- */

function fieldEditor({ label, value, hidden, onChange }) {
  const box = document.createElement("div");
  box.className = "edfield";
  box.style.cssText = "display:flex;gap:6px;margin-bottom:6px";
  const lbl = document.createElement("input");
  lbl.type = "text";
  lbl.placeholder = "Label";
  lbl.value = label || "";
  const val = document.createElement("input");
  val.type = "text";
  val.placeholder = "Value";
  val.autocomplete = "off";
  val.value = value || "";
  const hide = document.createElement("input");
  hide.type = "checkbox";
  hide.checked = !!hidden;
  hide.title = "Hidden (masked when copied)";
  const del = document.createElement("button");
  del.textContent = "×";
  del.className = "ghost small";
  del.style.cssText = "flex:none;width:28px;padding:4px 0";
  const commit = () => onChange({ label: lbl.value, value: val.value, hidden: hide.checked });
  lbl.addEventListener("input", commit);
  val.addEventListener("input", commit);
  hide.addEventListener("change", commit);
  del.addEventListener("click", () => box.remove());
  box.append(lbl, val, hide, del);
  return box;
}

function addCustomFieldRow(existing) {
  const wrap = $("ed-fields");
  const row = fieldEditor(existing || {});
  wrap.append(row);
  row._existing = existing && (existing.label !== undefined);
  return row;
}

async function openEditor(entry) {
  editorState = entry ? { mode: "edit", entry } : { mode: "new" };
  $("editor-error").hidden = true;
  $("btn-edit-delete").hidden = !entry;

  $("ed-type").value = entry ? (entry.type || "LOGIN") : "LOGIN";
  $("ed-title").value = entry ? (entry.title || "") : "";
  $("ed-username").value = entry ? (entry.username || "") : "";
  $("ed-password").value = entry ? (entry.password || "") : "";
  $("ed-url").value = entry ? (entry.url || "") : "";
  $("ed-notes").value = entry ? (entry.notes || "") : "";
  const hasTotp = !!(entry && (entry.totpSecret || "").trim());
  $("ed-totp-secret").value = hasTotp ? entry.totpSecret : "";
  $("ed-totp-algo").value = entry && (entry.totpAlgorithm || "SHA1");
  $("ed-totp-digits").value = entry && entry.totpDigits ? entry.totpDigits : "";
  $("ed-totp-period").value = entry && entry.totpPeriodSeconds ? entry.totpPeriodSeconds : "";
  $("ed-favorite").checked = !!(entry && entry.favorite);
  $("ed-fields").textContent = "";
  for (const f of (entry && entry.customFields) || []) addCustomFieldRow(f);
  if (!entry) addCustomFieldRow({}); // an empty starter row

  applyTypeFields();
  show("screen-editor");
  $("ed-title").focus();
}

$("screen-editor").addEventListener("keydown", (e) => {
  if (e.key === "Escape") { e.preventDefault(); renderTab(); return; }
  if (e.key === "Enter" && e.target.tagName === "INPUT" && e.target.type !== "checkbox") {
    e.preventDefault();
    $("btn-edit-save").click();
  }
});

function applyTypeFields() {
  const type = $("ed-type").value;
  for (const el of document.querySelectorAll(".login-only")) {
    el.hidden = !(type === "LOGIN");
  }
  for (const el of document.querySelectorAll(".totp-only")) {
    el.hidden = !(type === "LOGIN" || type === "TOTP");
  }
}

$("ed-type").addEventListener("change", applyTypeFields);
$("btn-add-field").addEventListener("click", () => addCustomFieldRow({}));

$("btn-edit-cancel").addEventListener("click", () => renderTab());
$("btn-edit-delete").addEventListener("click", async () => {
  const current = editorState && editorState.entry;
  if (!current) return;
  if (!confirm("Delete this entry from the vault?")) return;
  editorState = null;
  const r = await msg({ cmd: "deleteEntry", id: current.id });
  if (r && r.ok) return renderTab();
  alert(r && r.error ? r.error : "Delete failed");
});

$("btn-edit-save").addEventListener("click", async () => {
  const error = $("editor-error");
  error.hidden = true;
  const type = $("ed-type").value;
  const title = $("ed-title").value.trim();
  if (!title) {
    error.textContent = "Give the entry a name.";
    error.hidden = false;
    return;
  }
  let totpSecret = ($("ed-totp-secret").value || "").trim();
  let entryPart = {
    type,
    title,
  };
  if (type === "LOGIN") {
    entryPart.username = $("ed-username").value.trim() || null;
    entryPart.password = $("ed-password").value || null;
    entryPart.url = $("ed-url").value.trim() || null;
  } else if (type === "TOTP") {
    entryPart.totpSecret = totpSecret || null;
  }
  if (type === "LOGIN" || type === "TOTP") {
    if (totpSecret) {
      try { cvBase32Decode(totpSecret); }
      catch (e) {
        error.textContent = e.message || "Invalid TOTP secret";
        error.hidden = false;
        return;
      }
      entryPart.totpSecret = totpSecret;
      entryPart.totpAlgorithm = $("ed-totp-algo").value;
      entryPart.totpDigits = parseInt($("ed-totp-digits").value || "6", 10) || 6;
      entryPart.totpPeriodSeconds = parseInt($("ed-totp-period").value || "30", 10) || 30;
    } else {
      // secret cleared (or never set): remove TOTP params entirely
      entryPart.totpSecret = null;
      entryPart.totpAlgorithm = null;
      entryPart.totpDigits = null;
      entryPart.totpPeriodSeconds = null;
    }
  }
  entryPart.notes = $("ed-notes").value.trim() || null;
  const fields = [];
  for (const row of $("ed-fields").children) {
    const lbl = row.querySelector("input[type=text]").value.trim();
    const valEl = row.querySelectorAll("input")[1];
    const hiddenEl = row.querySelector("input[type=checkbox]");
    if (!lbl && !valEl.value.trim()) continue;
    const field = { label: lbl || "Field", value: valEl.value, hidden: !!hiddenEl.checked };
    fields.push(field);
  }
  const target = editorState.entry || {};
  entryPart.customFields = fields;
  entryPart.favorite = $("ed-favorite").checked;
  const full = Object.assign({}, target, entryPart);
  if (editorState.mode === "edit") full.id = editorState.entry.id;

  const btn = $("btn-edit-save");
  btn.disabled = true;
  btn.textContent = "Saving…";
  const res = await msg({ cmd: "upsertEntry", entry: full });
  btn.disabled = false;
  btn.textContent = "Save";
  if (!res || !res.ok) {
    error.textContent = (res && res.error) || "Save failed";
    error.hidden = false;
    return;
  }
  return renderTab();
});

/* ---------- tabs / lists ---------- */

$("tab-site").addEventListener("click", () => switchVaultTab("site"));
$("tab-vault").addEventListener("click", () => switchVaultTab("vault"));
$("btn-new").addEventListener("click", () => openEditor(null));

function switchVaultTab(which) {
  vaultTab = which;
  $("tab-site").classList.toggle("on", which === "site");
  $("tab-vault").classList.toggle("on", which === "vault");
  $("site-list").hidden = which !== "site";
  $("vault-list").hidden = which !== "vault";
  $("search").hidden = which !== "vault";
  $("entries-none").hidden = true;
  if (which === "vault") { $("search").value = ""; searchQuery = ""; }
  renderTab();
}

/* ---------- login / save-banner flows (v1.0, unchanged behaviour) ---------- */

async function login() {
  const email = $("login-email").value.trim();
  const password = $("login-password").value;
  const err = $("login-error");
  err.hidden = true;
  if (!email || !password) {
    err.textContent = "Enter your email and master password.";
    err.hidden = false;
    return;
  }
  const btn = $("btn-login");
  btn.textContent = "Deriving key…";
  btn.disabled = true;
  const res = await msg({ cmd: "login", email, password });
  btn.textContent = "Unlock";
  btn.disabled = false;
  $("login-password").value = "";
  if (res && res.ok) {
    $("login-email").value = "";
    return renderTab();
  }
  err.textContent = (res && (res.error || res.message)) || "Sign-in failed.";
  err.hidden = false;
  return renderTab();
}

/* ---------- search filter, reveal toggle, password generator ---------- */

let searchQuery = "";
let lastLists = { site: null, vault: null };

$("search").addEventListener("input", () => {
  searchQuery = $("search").value.trim().toLowerCase();
  if (vaultTab === "vault" && lastLists.vault) renderVaultList(lastLists.vault);
  else if (lastLists.site) renderSiteList(lastLists.site);
});

function matchesSearch(e) {
  if (!searchQuery) return true;
  return (String(e.title || "") + " " + String(e.username || "") +
    " " + String(e.url || "")).toLowerCase().includes(searchQuery);
}

/** Unbiased random password: class picks + shuffle, rejection sampling. */
function cvGenPassword(len = 32) {
  len = Math.max(12, Math.min(64, len));
  const classes = [
    "abcdefghijkmnopqrstuvwxyz",
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "23456789",
    "!@#$%^&*()-_=+[]{}?",
  ];
  const all = classes.join("");
  const rand = (n, count) => {
    const out = new Uint32Array(count);
    const buf = new Uint32Array(count);
    const limit = Math.floor(0x100000000 / n) * n;
    crypto.getRandomValues(buf);
    for (let i = 0; i < count; i++) {
      let v = buf[i];
      while (v >= limit) { crypto.getRandomValues(new Uint32Array(buf.buffer, i * 4, 1)); v = buf[i]; }
      out[i] = v % n;
    }
    return Array.from(out);
  };
  const picks = [];
  for (const cls of classes) if (picks.length < len) picks.push(cls[rand(cls.length, 1)[0]]);
  const chars = picks.slice(0, len).concat(
    Array.from(rand(all.length, len - picks.length), (v) => all[v]));
  const order = chars.map((_, k) => k);
  for (let i = order.length - 1; i > 0; i--) {
    const j = rand(i + 1, 1)[0];
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order.map((k) => chars[k]).join("");
}

$("btn-reveal").addEventListener("click", () => {
  const el = $("ed-password");
  el.type = el.type === "password" ? "text" : "password";
});
$("btn-generate").addEventListener("click", () => {
  const el = $("ed-password");
  el.value = cvGenPassword(32);
  el.type = "text";
  setTimeout(() => { try { el.type = "password"; } catch {} }, 1200);
});

$("login-password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") login();
});
$("login-email").addEventListener("keydown", (e) => {
  if (e.key === "Enter") login();
});

async function renderTab() {
  const st = await msg({ cmd: "state" });
  if (!st || !st.authed) return lockUi();

  hint(st.email || "");
  $("btn-logout").hidden = false;
  setFoot(st.revision != null ? "revision " + st.revision : "");
  show("screen-entries");

  const url = tabInfo && tabInfo.url || "";
  const pending = await msg({ cmd: "getPending" });

  if (vaultTab === "site") {
    const e = await msg({ cmd: "entries", url });
    if (e && e.error && String(e.error).includes("Sign in")) { return lockUi(); }
    if (e && e.error) {
      $("entries-none").hidden = false;
      $("entries-none").textContent = e.error;
    } else {
      renderSiteList(e);
    }
  } else {
    const v = await msg({ cmd: "vault" });
    if (v && v.error) { return lockUi(); }
    renderVaultList(v);
    setFoot("revision " + v.revision);
  }

  // Save banner merges onto the list view
  if (pending && pending.pending &&
      pending.pending.url && hostOf(pending.pending.url) === hostOf(url)) {
    $("screen-save").hidden = false;
    $("save-summary").textContent =
      pending.pending.username + " → " + hostOf(pending.pending.url);
    $("save-title").value = hostOf(pending.pending.url);
  } else {
    $("screen-save").hidden = true;
  }
}

function lockUi() {
  editorState = null;
  viewerState = null;
  searchQuery = "";
  $("search").value = "";
  $("search").hidden = true;
  $("login-email").value = "";
  $("login-password").value = "";
  show("screen-login");
  $("btn-logout").hidden = true;
  setFoot("");
  hint("");
}

async function save() {
  const pending = (await msg({ cmd: "getPending" })).pending;
  if (!pending) return renderTab();
  const btn = $("btn-save");
  btn.disabled = true;
  btn.textContent = "Saving…";
  const res = await msg({
    cmd: "saveEntry",
    title: $("save-title").value.trim() || hostOf(pending.url),
    username: pending.username,
    password: pending.password,
    url: pending.url,
  });
  btn.textContent = "Save";
  btn.disabled = false;
  if (!(res && res.ok)) {
    $("save-summary").textContent = res.error || "Save failed — try again.";
    return;
  }
  await renderTab();
}

$("btn-login").addEventListener("click", login);
$("btn-save").addEventListener("click", save);
$("btn-discard").addEventListener("click", async () => {
  await msg({ cmd: "discard" });
  return renderTab();
});
$("btn-logout").addEventListener("click", async () => {
  await msg({ cmd: "logout" });
  return renderTab();
});

(async () => {
  tabInfo = await currentTab();
  renderTab();
})();
