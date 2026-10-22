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
  importScripts("crypto.js", "api.js", "domains.js");
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
  return { vault: JSON.parse(plain), session };
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
      vault = JSON.parse(plain);
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
      existing.password = password;
      existing.passwordUpdatedAt = now;
      existing.updatedAt = now;
      existing.revision = (existing.revision || 0) + 1;
    } else {
      vault.entries.push(cvEntryTemplate(now, title || host, username, password, url));
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

function cvClearTabBadge(tabId) {
  if (typeof chrome !== "undefined" && chrome.action && tabId != null) {
    chrome.action.setBadgeText({ tabId, text: "" }).catch?.(() => {});
  }
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
          const session = await cvGet("cvSession");
          if (session && session.sessionToken) {
            try { await CvApi.logout(session.sessionToken); } catch (e) { /* best effort */ }
          }
          await cvRemove(["cvSession", "cvPending"]);
          return { ok: true };
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

        default:
          return { error: "unknown_command" };
      }
    } catch (e) {
      return { error: (e && e.message) || "Something went wrong", status: e && e.status, code: e && e.error };
    }
  })().then(respond);
  return true;
});
