/**
 * CipherVault addon background worker.
 *
 * Keeps one signed-in session per browser in `storage.session` (cleared when
 * the browser closes — the derived key and vault never touch disk). Handles
 * login, logout, vault read, and save-with-merge; the popup and content
 * script never see key material, never receive answers with more than one
 * entry's credentials.
 */

// Chromium MV3 service worker: pull sibling modules into scope.
if (typeof importScripts === "function") {
  importScripts("crypto.js", "api.js", "domains.js", "totp.js");
}

// Prefer memory-backed session storage; fall back to local storage cleared on
// startup for engines without storage.session.
const CVStorage = (typeof chrome !== "undefined" && chrome.storage.session) ||
    (typeof browser !== "undefined" && browser.storage.session) ||
    (typeof chrome !== "undefined" ? chrome.storage.local : null);
const CVStorageIsSessional = CVStorage && CVStorage === chrome.storage.session;

if (!CVStorageIsSessional && typeof chrome !== "undefined" && chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    chrome.storage.local.remove(["cvSession", "cvPending"]);
  });
}

async function cvGet(key) {
  const o = await CVStorage.get([key]);
  return o[key];
}

async function cvSet(obj) {
  await CVStorage.set(obj);
}

async function cvRemove(keys) {
  await CVStorage.remove(keys);
}

// (cvRegistrableDomain comes from domains.js — same heuristic as the app.)

/** Repair a decrypted vault in place; shared by every read path. */
function cvSanitizeVault(vault) {
  if (!vault || typeof vault !== "object") {
    return { version: 1, revision: 0, entries: [], folders: [] };
  }
  if (!Array.isArray(vault.folders)) vault.folders = [];
  if (!Array.isArray(vault.entries)) vault.entries = [];
  const seenIds = new Set();
  vault.entries = vault.entries.filter((e) => e && typeof e === "object" && !Array.isArray(e));
  for (const e of vault.entries) {
    if (typeof e.id !== "string" || !e.id) e.id = "cvext-" + crypto.randomUUID();
    while (seenIds.has(e.id)) { e.id = "cvext-" + crypto.randomUUID(); }
    seenIds.add(e.id);
    if (!["LOGIN", "NOTE", "CARD", "IDENTITY", "TOTP"].includes(e.type)) e.type = "LOGIN";
    if (typeof e.title !== "string") e.title = "";
    if (!Array.isArray(e.customFields)) e.customFields = [];
  }
  return vault;
}

/** Decrypt the stored cipher, refreshing it from the server when stale. */
async function cvVault(session) {
  const latest = await CvApi.getBlob(session.sessionToken);
  if (latest.revision !== session.blobRevision && latest.ciphertext) {
    session.cipherB64 = latest.ciphertext;
    session.blobRevision = latest.revision;
  }
  if (!session.cipherB64) {
    return { vault: { version: 1, revision: 0, entries: [], folders: [] }, session };
  }
  const stored = cvB64decode(session.cipherB64);
  const aad = "CipherVault/v1/" + session.userId + "/" + latest.revision;
  const plain = await cvOpen(cvB64decode(session.cipherKeyB64), stored, aad);
  return { vault: cvSanitizeVault(JSON.parse(plain)), session };
}

const CV_EMPTY_VAULT = Object.freeze({ version: 1, revision: 0, entries: [], folders: [] });

function cvLiveLogins(vault) {
  return (vault.entries || []).filter(
    (e) => !e.deletedAt && e.type === "LOGIN" && e.title && e.username,
  );
}

function cvEntryTemplate(now, title, username, password, url) {
  return {
    id: "local-" + now,
    type: "LOGIN",
    title,
    username,
    password,
    totpSecret: null,
    totpAlgorithm: null,
    totpDigits: null,
    totpPeriodSeconds: null,
    url,
    notes: null,
    folder: null,
    favorite: false,
    customFields: [],
    createdAt: now,
    updatedAt: now,
    revision: 1,
    deletedAt: null,
    passwordUpdatedAt: now,
    lastUsedAt: null,
  };
}

/** Merge-type save: pull → edit → seal(at base_revision+1) → push; retry on 409. */
async function cvSaveEntry(session, { title, username, password, url }) {
  const host = cvRegistrableDomain(url);
  for (let attempt = 0; attempt < 3; attempt++) {
    let vault;
    const fresh = await CvApi.getBlob(session.sessionToken);
    if (fresh.ciphertext) {
      const aad = "CipherVault/v1/" + session.userId + "/" + fresh.revision;
      const plain = await cvOpen(cvB64decode(session.cipherKeyB64), cvB64decode(fresh.ciphertext), aad);
      vault = cvSanitizeVault(JSON.parse(plain));
    } else {
      vault = JSON.parse(JSON.stringify(CV_EMPTY_VAULT));
    }
    if (!Array.isArray(vault.folders)) vault.folders = [];

    const now = Date.now();
    const existing = vault.entries.find(
      (e) => !e.deletedAt && e.type === "LOGIN" &&
        e.username === username && cvRegistrableDomain(e.url) === host,
    );
    if (existing) {
      if (existing.password === password) {
        return { ok: true, saved: false, reason: "already-saved" };
      }
      const clean = cvNormalizeEntry(existing);
      clean.password = typeof password === "string" ? password.slice(0, 1000) : null;
      existing.password = clean.password;
      existing.updatedAt = now;
      existing.passwordUpdatedAt = now;
      existing.revision = (existing.revision || 0) + 1;
    } else {
      const clean = cvNormalizeEntry({
        type: "LOGIN",
        title: title || host,
        username,
        password,
        url,
      });
      clean.id = "local-" + now;
      clean.createdAt = now;
      clean.passwordUpdatedAt = now;
      vault.entries.push(clean);
    }

    const sealed = await cvSeal(
      cvB64decode(session.cipherKeyB64),
      JSON.stringify(vault),
      "CipherVault/v1/" + session.userId + "/" + (fresh.revision + 1),
    );
    try {
      const pushed = await CvApi.putBlob(
        session.sessionToken, cvB64encode(sealed), fresh.revision,
      );
      session.cipherB64 = cvB64encode(sealed);
      session.blobRevision = pushed.revision || (fresh.revision + 1);
      await cvSet({ cvSession: session });
      return { ok: true, saved: true };
    } catch (e) {
      if (e && (e.status === 409 || e.error === "conflict")) continue;
      throw e;
    }
  }
  throw { status: 409, error: "conflict", message: "Vault is changing fast — try saving again" };
}

function cvEntryDefaults(now) {
  return {
    id: "cvext-" + crypto.randomUUID(),
    type: "LOGIN",
    title: "",
    username: null,
    password: null,
    totpSecret: null,
    totpAlgorithm: null,
    totpDigits: null,
    totpPeriodSeconds: null,
    url: null,
    notes: null,
    folder: null,
    favorite: false,
    customFields: [],
    createdAt: now,
    updatedAt: now,
    revision: 1,
    deletedAt: null,
    passwordUpdatedAt: now,
    lastUsedAt: null,
  };
}

/**
 * Whitelist-and-clamp everything the client (popup) writes. Unknown keys are
 * dropped here; any type/length violation falls back to the type default so
 * a hostile or buggy caller can never poison the vault shape.
 */
function cvNormalizeEntry(raw) {
  const out = cvEntryDefaults(Date.now());
  const src = raw && typeof raw === "object" ? raw : {};
  const str = (v, max) => {
    const s = typeof v === "string" ? v : v == null ? "" : String(v);
    const t = s.trim();
    return t ? t.slice(0, max) : null;
  };

  const types = ["LOGIN", "NOTE", "CARD", "IDENTITY", "TOTP"];
  out.type = types.includes(src.type) ? src.type : "LOGIN";
  out.title = str(src.title, 200) || "";
  out.notes = str(src.notes, 10000);
  out.favorite = !!src.favorite;
  out.folder = out.type === "LOGIN" ? str(src.folder, 120) : null;

  if (out.type === "LOGIN") {
    out.username = str(src.username, 320);
    out.password = typeof src.password === "string"
      ? src.password.slice(0, 1000) || null : null;
    const url = str(src.url, 2000);
    if (url) {
      try {
        const u = new URL(url);
        out.url = /^https?:$/.test(u.protocol) ? u.href : null;
      } catch { out.url = null; }
    }
  } else {
    out.username = null;
    out.password = null;
    out.url = null;
  }

  if (out.type === "LOGIN" || out.type === "TOTP") {
    let secret = src.totpSecret == null ? "" : String(src.totpSecret).trim().slice(0, 220);
    if (secret) {
      try {
        cvBase32Decode(secret);
        secret = secret.toUpperCase();
        out.totpSecret = secret;
        out.totpAlgorithm = ["SHA1", "SHA256", "SHA512"].includes(String(src.totpAlgorithm || "").toUpperCase())
          ? String(src.totpAlgorithm).toUpperCase() : "SHA1";
        const digits = parseInt(src.totpDigits, 10) || 6;
        const period = parseInt(src.totpPeriodSeconds, 10) || 30;
        out.totpDigits = Math.max(6, Math.min(10, digits));
        out.totpPeriodSeconds = Math.max(10, Math.min(120, period));
      } catch { /* invalid seed → no TOTP params */ }
    }
  }

  if (Array.isArray(src.customFields)) {
    out.customFields = src.customFields.slice(0, 50).map((f) => ({
      label: str(f && f.label, 64) || "Field",
      value: f && typeof f.value === "string"
        ? f.value.slice(0, 2000) || null : null,
      hidden: !!(f && f.hidden),
    })).filter((f) => f.value != null || f.label !== "Field");
  }
  return out;
}

/**
 * Add/edit (id present → replace; absent → insert) or tombstone-delete a
 * single entry, with the same pull → seal(base+1) → push → 409-retry dance
 * the capture-save uses.
 */
async function cvUpsertEntry(session, { entry, remove }) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const fresh = await CvApi.getBlob(session.sessionToken);
    let vault;
    if (fresh.ciphertext) {
      const aad = "CipherVault/v1/" + session.userId + "/" + fresh.revision;
      const plain = await cvOpen(cvB64decode(session.cipherKeyB64), cvB64decode(fresh.ciphertext), aad);
      vault = cvSanitizeVault(JSON.parse(plain));
    } else {
      vault = JSON.parse(JSON.stringify(CV_EMPTY_VAULT));
    }
    if (!Array.isArray(vault.folders)) vault.folders = [];
    if (!Array.isArray(vault.entries)) vault.entries = [];

    const now = Date.now();
    if (remove) {
      const id = typeof entry.id === "string" ? entry.id.trim() : "";
      const idx = id ? vault.entries.findIndex((e) => e.id === id) : -1;
      const existing = idx >= 0 ? vault.entries[idx] : null;
      if (!existing || existing.deletedAt) return { ok: true, revision: fresh.revision };
      existing.deletedAt = now;
      existing.updatedAt = now;
      existing.revision = (existing.revision || 0) + 1;
    } else {
      // Only a non-empty, client-provided id addressing a real entry triggers
      // the edit path; tombstones (or empty-ish ids) are never resurrected
      // implicitly when the popup merely forgot the id.
      const providedId = typeof entry.id === "string" ? entry.id.trim() : "";
      const idx = providedId
        ? vault.entries.findIndex((e) => e.id === providedId) : -1;
      const existing = idx >= 0 ? vault.entries[idx] : null;
      const clean = cvNormalizeEntry(entry);
      const finished = {
        id: providedId || clean.id,
        type: clean.type,
        title: clean.title,
        username: clean.username,
        password: clean.password,
        totpSecret: clean.totpSecret,
        totpAlgorithm: clean.totpAlgorithm,
        totpDigits: clean.totpDigits,
        totpPeriodSeconds: clean.totpPeriodSeconds,
        url: clean.url,
        notes: clean.notes,
        folder: clean.folder,
        favorite: clean.favorite,
        customFields: clean.customFields,
      };
      if (existing) {
        // Union-merge: fields the client sent win, unknown/unsent fields
        // (folder, lastUsedAt, app-only keys…) survive from the existing entry.
        const wasPassword = existing.password !== finished.password;
        vault.entries[idx] = Object.assign({}, existing, finished, {
          id: existing.id,
          createdAt: existing.createdAt,
          revision: (existing.revision || 0) + 1,
          updatedAt: now,
          deletedAt: null, // editing a tombstone resurrects it, app-style
          passwordUpdatedAt: wasPassword ? now : (existing.passwordUpdatedAt || now),
        });
      } else {
        vault.entries.push(Object.assign({}, cvEntryDefaults(now), finished, {
          id: providedId || clean.id,
          createdAt: now,
          revision: 1,
          updatedAt: now,
          passwordUpdatedAt: now,
        }));
      }
    }

    const sealed = await cvSeal(
      cvB64decode(session.cipherKeyB64),
      JSON.stringify(vault),
      "CipherVault/v1/" + session.userId + "/" + (fresh.revision + 1),
    );
    try {
      const pushed = await CvApi.putBlob(
        session.sessionToken, cvB64encode(sealed), fresh.revision,
      );
      session.cipherB64 = cvB64encode(sealed);
      session.blobRevision = pushed.revision || (fresh.revision + 1);
      await cvSet({ cvSession: session });
      return { ok: true, revision: session.blobRevision };
    } catch (e) {
      if (e && (e.status === 409 || e.error === "conflict")) continue;
      throw e;
    }
  }
  throw { status: 409, error: "conflict", message: "Vault is changing fast — try again" };
}

function cvClearTabBadge(tabId) {
  if (typeof chrome !== "undefined" && chrome.action && tabId != null) {
    chrome.action.setBadgeText({ tabId, text: "" }).catch?.(() => {});
  }
}

/* ---------- auto-lock (professional default: 15 minutes idle) ---------- */
const CV_IDLE_MINUTES = 15;

async function cvLockSession() {
  const session = await cvGet("cvSession");
  if (session && session.sessionToken) {
    try { await CvApi.logout(session.sessionToken); } catch (e) { /* best effort */ }
  }
  await cvRemove(["cvSession", "cvPending"]);
  cvClearTabBadge(null);
  return { ok: true };
}

if (typeof chrome !== "undefined" && chrome.idle && chrome.idle.onStateChanged) {
  try {
    chrome.idle.setDetectionInterval(CV_IDLE_MINUTES * 60);
    chrome.idle.onStateChanged.addListener((state) => {
      if (state === "locked" || state === "idle") {
        cvGet("cvSession").then((s) => {
          if (s && s.sessionToken) cvLockSession();
        });
      }
    });
  } catch (e) { /* idle unavailable */ }
}

/** Message router. */
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  (async () => {
    try {
      switch (msg && msg.cmd) {
        case "state": {
          const session = await cvGet("cvSession");
          return {
            authed: !!(session && session.sessionToken),
            email: session ? session.email : null,
            revision: session ? session.blobRevision : null,
            sessional: CVStorageIsSessional,
          };
        }

        case "login": {
          const email = String(msg.email || "").trim().toLowerCase();
          if (!email.includes("@")) throw { message: "Enter a valid email" };
          const pl = await CvApi.prelogin(email);
          if (pl.kdf && pl.kdf.algo && pl.kdf.algo !== "PBKDF2_SHA256") {
            throw {
              message: "This vault uses " + pl.kdf.algo + " after a migration. Unlock it in " +
                "the CipherVault app; the addon currently signs in to PBKDF2 vaults.",
            };
          }
          const salt = cvB64decode(pl.kdf_salt);
          const masterBits = await cvDeriveMaster(msg.password, salt, pl.kdf.iterations);
          const authKey = await cvAuthKey(masterBits);
          const encKey = await cvEncKey(masterBits);
          masterBits.fill(0);
          const login = await CvApi.login(email, cvB64encode(authKey), "CipherVault Addon");
          const session = {
            email,
            userId: login.user_id,
            sessionToken: login.session_token,
            cipherKeyB64: cvB64encode(encKey),
            cipherB64: null,
            blobRevision: login.vault_revision,
          };
          try {
            const blob = await CvApi.getBlob(session.sessionToken);
            session.cipherB64 = blob.ciphertext || null;
            session.blobRevision = blob.revision;
          } catch (e) { /* vault read can be retried later */ }
          await cvSet({ cvSession: session });
          await cvRemove(["cvPending"]);
          return { ok: true, email, revision: session.blobRevision };
        }

        case "logout": {
          return cvLockSession();
        }

        case "entries": {
          const session = await cvGet("cvSession");
          if (!session || !session.sessionToken) throw { message: "Sign in first" };
          let vault;
          let session_ = session;
          if (session.cipherB64) {
            const stored = cvB64decode(session.cipherB64);
            const aad = "CipherVault/v1/" + session.userId + "/" + session.blobRevision;
            let plain;
            try {
              plain = await cvOpen(cvB64decode(session.cipherKeyB64), stored, aad);
              vault = JSON.parse(plain);
            } catch (e) {
              ({ vault, session: session_ } = await cvVault(session));
            }
          } else {
            ({ vault, session: session_ } = await cvVault(session));
          }
          await cvSet({ cvSession: session_ });
          const host = cvRegistrableDomain(msg.url || "");
          const all = cvLiveLogins(vault);
          const matched = host
            ? all.filter((e) => cvRegistrableDomain(e.url) === host)
            : [];
          return {
            ok: true,
            revision: session_.blobRevision,
            matched,
            others: all.length - matched.length,
            total: all.length,
          };
        }
        case "submitDetected": {
          const session = await cvGet("cvSession");
          if (!session || !session.sessionToken) return { ok: false };
          const { username, password, url, tabId } = msg;
          if (!username || !password || !url) return { ok: false };
          let vault;
          try { ({ vault } = await cvVault(session)); } catch { return { ok: false }; }
          const host = cvRegistrableDomain(url);
          const dup = vault.entries.some(
            (e) => !e.deletedAt && e.type === "LOGIN" &&
              e.username === username &&
              cvRegistrableDomain(e.url) === host,
          );
          if (dup) return { ok: false };
          await cvSet({
            cvPending: { username, password, url, at: Date.now() },
          });
          if (typeof chrome !== "undefined" && chrome.action) {
            try { await chrome.action.setBadgeText({ tabId, text: "1", }); } catch {}
            try { await chrome.action.setBadgeBackgroundColor({ tabId, color: "#0B6B47" }); } catch {}
          }
          return { ok: true, offered: true };
        }

        case "getPending": {
          const pending = await cvGet("cvPending");
          const fresh = pending && Date.now() - pending.at < 30 * 60 * 1000 ? pending : null;
          if (!fresh) await cvRemove(["cvPending"]);
          return { ok: true, pending: fresh };
        }

        case "discard": {
          await cvRemove(["cvPending"]);
          cvClearTabBadge(sender && sender.tab ? sender.tab.id : null);
          return { ok: true };
        }

        case "saveEntry": {
          const session = await cvGet("cvSession");
          if (!session || !session.sessionToken) throw { message: "Sign in first" };
          const result = await cvSaveEntry(session, msg);
          await cvRemove(["cvPending"]);
          cvClearTabBadge(sender && sender.tab ? sender.tab.id : null);
          return result;
        }

        case "vault": {
          const session = await cvGet("cvSession");
          if (!session || !session.sessionToken) throw { message: "Sign in first" };
          const { vault, session: _fresh } = await cvVault(session);
          await cvSet({ cvSession: _fresh });
          return {
            ok: true,
            revision: _fresh.blobRevision,
            entries: (vault.entries || [])
              .filter((e) => !e.deletedAt)
              .map((e) => ({
                id: e.id,
                type: e.type || "LOGIN",
                title: e.title || "",
                username: e.username || null,
                url: e.url || null,
                folder: e.folder || null,
                favorite: !!e.favorite,
                hasTotp: !!(e.totpSecret || "").trim(),
                customFields: e.customFields && e.customFields.length ? true : false,
              })),
          };
        }

        case "getEntry": {
          const session = await cvGet("cvSession");
          if (!session || !session.sessionToken) throw { message: "Sign in first" };
          const { vault, session: _f2 } = await cvVault(session);
          await cvSet({ cvSession: _f2 });
          const entry = (vault.entries || []).find(
            (e) => !e.deletedAt && e.id === msg.id,
          );
          if (!entry) throw { message: "Entry not found", status: 404, error: "not_found" };
          return { ok: true, entry };
        }

        case "upsertEntry": {
          const session = await cvGet("cvSession");
          if (!session || !session.sessionToken) throw { message: "Sign in first" };
          return cvUpsertEntry(session, { entry: msg.entry, remove: false });
        }

        case "deleteEntry": {
          const session = await cvGet("cvSession");
          if (!session || !session.sessionToken) throw { message: "Sign in first" };
          return cvUpsertEntry(session, { entry: { id: String(msg.id) }, remove: true });
        }

        default:
          return { error: "unknown_command" };
      }
    } catch (e) {
      return { error: (e && e.message) || "Something went wrong", status: e && e.status, code: e && e.error };
    }
  })().then(respond);
  return true;
});
