# Privacy Policy — CipherVault

**Effective date:** 16 October 2026

## Summary

CipherVault is a zero-knowledge password manager. Your vault contents are
encrypted on your device before they are sent to our server. We cannot
read your passwords, notes, cards or authenticator secrets, and we cannot
recover your master password for you.

## Data we store

| Data | Why | Where |
| --- | --- | --- |
| Email address | Account identity, sign-in | Server database |
| Password verifier (a hash derived from your master password) | Proves your password at sign-in without ever transmitting it | Server database |
| Encrypted vault blob and its revision number | Sync between your devices | Server database |
| KDF parameters and salt | Key derivation on your devices | Server database |
| Session records (issue time, device name, last activity) | "Sign out other devices" and session management | Server database |
| Security audit events (sign-in success/failure, sync, password or KDF changes, timestamps, IP address, coarse device name) | Abuse detection and the in-app Security activity log | Server database |
| Rate-limit counters keyed by IP | Prevent brute force | Server memory/database |

We do not collect contacts, location, advertising identifiers, or usage
analytics. There are no third-party analytics, advertising or tracking
SDKs in the app. QR barcode scanning for two-factor secrets happens
entirely on the device (Google ML Kit, on-device model); scanned data is
never uploaded.

## What we cannot see

Vault items (passwords, usernames, notes, cards, identities, TOTP
secrets) are encrypted with a key derived from your master password using
Argon2id (or PBKDF2-SHA256 for accounts created before the current
default). The server stores ciphertext only. Anyone who obtains our
database copy still cannot read your vault without your master password.

## Sessions and revocation

Changing your master password from the app re-encrypts the vault and
signs out every other device. The Settings screen lists active sessions
and lets you sign out other devices at any time.

## Data retention

Accounts and their server-side data are retained while the account exists.
Deleting the app does not delete the server account; contact the operator
to request account deletion. Security audit events are retained for the
account's lifetime so the in-app activity log stays accurate.

## Security

Data in transit is protected by TLS; the Android app pins the server's
certificate chain. Vault blobs are additionally authenticated with
AES-256-GCM bound to your account id and revision number. Release builds
block screenshots of the app while it is open, and copied secrets are
cleared from the clipboard after a short timeout.

No system is perfectly secure. If we learn of a vulnerability affecting
your data we will disclose it and, where possible, notify affected
accounts.

## Children

The app is not directed at children under 13 (or the minimum age required
in your jurisdiction).

## Changes

Material changes to this policy will be reflected here with an updated
effective date, and in the app's changelog where appropriate.

## Contact

Operator: swapnashu — open an issue on
https://github.com/swapnashu/ciphervault
