# CipherVault browser add-on

Fill and save logins with your CipherVault vault from Chromium and Firefox.
Same zero-knowledge protocol as the mobile app: on this device we only ever
hold **derived keys + the encrypted vault blob** — never your master password.

- Sign in once per browser session (the session lives in `storage.session`
  and is dropped when the browser closes).
- The **Fill** button in the popup types username + password into the page's
  login form (works with React/managed inputs).
- Submitting a login form that isn't already saved raises a
  **"Save this login?"** banner in the popup; saving pulls, merges and pushes
  the vault blob (base_revision / revision + 1 like every other client).

## Install (load unpacked)

1. Download the zip for your browser from
   [Releases](https://github.com/swapnashu/ciphervault/releases) (`addon-*`)
   and unzip it, or build from source: `python build.py`
2. **Chrome / Edge / Brave** — `chrome://extensions` → enable *Developer mode*
   → *Load unpacked* → select the unzipped folder.
3. **Firefox** — `about:debugging#/runtime/this-firefox` → *Load Temporary
   Add-on…* → select `manifest.json` inside the unzipped folder.
4. Click the vault icon, sign in with your CipherVault email + master
   password. PBKDF2 vaults sign in directly; Argon2id vaults (post-migration)
   say to unlock in the app first — WebCrypto has no Argon2 yet.

## Source map

```
manifest.chromium.json   MV3 service-worker manifest (Chromium-family)
manifest.firefox.json    MV3 event-page manifest (Firefox), same UI
build.py                 copies common/ + icons/ + one manifest per target,
                         zips into dist/ (ciphervault-addon-<v>-{chromium,firefox}.zip)
common/
  crypto.js              PBKDF2 → HKDF master/auth/enc + AES-256-GCM blob
                         framing identical to the app: [1][12B IV][ct||tag],
                         AAD "CipherVault/v1/{userId}/{revision}"
  api.js                 vault wire client (health/prelogin/login/logout/blob)
  domains.js             registrable-domain matching (app-parity heuristics)
  background.js          session state, vault pull/decrypt/merge/push,
                         save-capture pipeline, badge
  content.js             login-form detection, fill with React-safe value
                         setters, submit/Enter capture
  popup.html/css/js      sign-in, save banner, per-site entry list + Fill
icons/                   16/32/48/128 green keyhole set
```

Verified end-to-end against the production server: derives the same keys as
the app, decrypts a real vault blob, refuses wrong-revision AADs, and pushes
a merged revision that a fresh pull reads back.

## Limitations (v1)

- Login fill/save only — no vault editing, TOTP, or field-by-field pickers.
- PBKDF2 accounts only (Argon2id accounts see a friendly pointer to the app).
- FF/Chromium stores not used; "load unpacked" is the supported path.
