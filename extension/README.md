# CipherVault browser add-on

Fill and save logins, browse your whole vault, and use TOTP — with your
CipherVault vault from Chromium and Firefox. Same zero-knowledge protocol as
the mobile app: on this device we only ever hold **derived keys + the
encrypted vault blob** — never your master password.

- Sign in once per browser session (the session lives in `storage.session`,
  is auto-locked after 15 idle minutes, and is dropped when the browser
  closes).
- The **Fill** button in the popup types username + password into the page's
  login form (works with React/managed inputs); entries with a TOTP seed get
  the current **one-time code** into `autocomplete="one-time-code"` fields.
- Submitting a login form that isn't already saved raises a
  **"Save this login?"** banner in the popup; saving pulls, merges and pushes
  the vault blob (base_revision / revision + 1 like every other client).
- **Vault editing (v1.1):** add / edit / delete every entry type — logins,
  notes, cards, identities, TOTP — with custom fields; titles, usernames,
  URLs, seeds and all values are validated and clamped on the trusted side.
- **Power tools:** live search across the vault, favourites, unbiased
  32-char password generator, per-row TOTP chips and a live code viewer.

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
  totp.js                RFC 6238 TOTP / RFC 4226 HOTP (verified against the
                         RFC's Appendix B vectors), base32 decoder
  api.js                 vault wire client (health/prelogin/login/logout/blob),
                         https-only base URL + path validation + 20s timeout
  domains.js             registrable-domain matching (app-parity heuristics)
  background.js          session state (auto-lock via chrome.idle), vault
                         pull/decrypt/merge/push, field whitelist + clamps,
                         save-capture pipeline, badge
  content.js             login-form detection, fill with React-safe value
                         setters, submit/Enter capture, one-time-code fill
  popup.html/css/js      sign-in, search, save banner, per-site entry list +
                         Fill, full vault list with editor + viewer, TOTP
                         chips (list) and live codes (viewer)
icons/                   16/32/48/128 green keyhole set
```

Verified end-to-end against the production server (12/12 + 25/25 live-CDP
checks): same keys as the app, encrypted round-trips of every entry type,
edit-retitle-delete bookkeeping, TOTP chips matching RFC window codes, save
capture/dedup guard, search, upload caps and wrong-revision AAD refusals.

## Limitations (v1.1)

- PBKDF2 accounts only (Argon2id accounts see a friendly pointer to the app).
- FF/Chromium stores not used; "load unpacked" is the supported path.
