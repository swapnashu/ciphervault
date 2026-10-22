/**
 * CipherVault popup — sign in, fill from the vault, save new logins.
 */

const $ = (id) => document.getElementById(id);
const screens = ["screen-login", "screen-save", "screen-entries"];

function show(...ids) {
  for (const s of screens) $(s).hidden = !ids.includes(s);
}

function hint(text) {
  $("state-hint").textContent = text || "";
}

function setFoot(text) {
  $("foot-rev").textContent = text;
}

function lockUi() {
  show("screen-login");
  $("btn-logout").hidden = true;
  setFoot("");
  hint("");
}

async function sendMessage(msg) {
  return chrome.runtime.sendMessage(msg) || {};
}

let tabInfo = null;

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

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
  const res = await sendMessage({ cmd: "login", email, password });
  btn.textContent = "Sign in";
  btn.disabled = false;
  $("login-password").value = "";
  if (res && res.ok) {
    $("login-email").value = "";
    return renderTab();
  }
  err.textContent = res.error || "Sign-in failed.";
  err.hidden = false;
  return renderTab();
}

async function renderTab() {
  const st = await sendMessage({ cmd: "state" });
  if (!st || !st.authed) return lockUi();

  hint(st.email ? st.email : "");
  $("btn-logout").hidden = false;
  setFoot(st.revision != null ? "revision " + st.revision : "");

  const tab = tabInfo || await currentTab();
  const url = tab && tab.url || "";
  const pending = await sendMessage({ cmd: "getPending" });

  drawEntriesPending: {
    const msg = await sendMessage({ cmd: "entries", url });
    if (msg && msg.error) return lockUi();

    // Save banner
    if (pending && pending.pending &&
        pending.pending.url && hostOf(pending.pending.url) === hostOf(url)) {
      $("screen-save").hidden = false;
      show("screen-save", "screen-entries");
      $("save-summary").textContent =
        pending.pending.username + " → " + hostOf(pending.pending.url);
      $("save-title").value = hostOf(pending.pending.url);
    } else {
      show("screen-entries");
      $("screen-save").hidden = true;
    }

    // Entry list
    const list = $("entries-list");
    list.textContent = "";
    const matched = msg.matched || [];
    if (!matched.length) {
      $("entries-none").hidden = false;
      $("entries-none").textContent = msg.total
        ? "No logins match this site (" + msg.total + " stored overall)."
        : "No logins stored yet. Save one from a login form, or add entries in the app.";
    } else {
      $("entries-none").hidden = true;
      for (const entry of matched) {
        const row = document.createElement("div");
        row.className = "entry";

        const who = document.createElement("div");
        who.className = "who";
        const t = document.createElement("b");
        t.textContent = entry.title || "";
        const u = document.createElement("span");
        u.textContent = entry.username || "";
        who.append(t, u);

        const fill = document.createElement("button");
        fill.textContent = "Fill";
        fill.addEventListener("click", async () => {
          try {
            await chrome.tabs.sendMessage(tab.id, {
              cmd: "cvFill",
              username: entry.username,
              password: entry.password,
            });
            window.close();
          } catch {
            t.textContent = (entry.title || "") + " (reload the page)";
          }
        });

        row.append(who, fill);
        list.append(row);
      }
    }
  }
}

function hostOf(value) {
  try { return new URL(value).host || ""; } catch { return ""; }
}

async function save() {
  const pending = (await sendMessage({ cmd: "getPending" })).pending;
  if (!pending) return renderTab();
  const btn = $("btn-save");
  btn.disabled = true;
  btn.textContent = "Saving…";
  const res = await sendMessage({
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
$("login-password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { login(); }
});
$("btn-save").addEventListener("click", save);
$("btn-discard").addEventListener("click", async () => {
  await sendMessage({ cmd: "discard" });
  return renderTab();
});
$("btn-logout").addEventListener("click", async () => {
  await sendMessage({ cmd: "logout" });
  return renderTab();
});

(async () => {
  tabInfo = await currentTab();
  renderTab();
})();
