/**
 * TOTP (RFC 6238 over RFC 4226) for the add-on, ported from the app's
 * crypto/Totp.kt and verified against the RFC 6238 Appendix B vectors.
 *
 *   code = HOTP(secret, floorDiv(unixSeconds, period), digits, algorithm)
 *   HOTP: HMAC(algorithm)(8-byte BE counter) -> dynamic truncation -> % 10^digits
 */

const CV_B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function cvBase32Decode(input) {
  const lookup = {};
  for (let i = 0; i < CV_B32_ALPHABET.length; i++) {
    lookup[CV_B32_ALPHABET[i]] = i;
    lookup[CV_B32_ALPHABET[i].toLowerCase()] = i;
  }
  const cleaned = [];
  for (const ch of String(input || "")) {
    if (ch === "=" || " \t\r\n\f\v".includes(ch)) continue;
    cleaned.push(ch);
  }
  const out = new Uint8Array(Math.floor((cleaned.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const ch of cleaned) {
    const value = ch.length === 1 && ch.charCodeAt(0) < 128 ? lookup[ch] : undefined;
    if (value === undefined) throw new Error("Invalid Base32 character: '" + ch + "'");
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >>> bits) & 0xFF;
    }
  }
  if (bits > 0 && bits >= 5) throw new Error("truncated Base32 input");
  return out.subarray(0, index);
}

function cvTotpAlgorithm(uriName) {
  // Same default as the app: unknown algorithm strings fall back to SHA1.
  const name = String(uriName || "SHA1").toUpperCase();
  if (name === "SHA256") return { alg: "SHA-256", block: 64 };
  if (name === "SHA512") return { alg: "SHA-512", block: 128 };
  return { alg: "SHA-1", block: 64 };
}

/** HOTP code for an 8-byte big-endian counter, app-parity digits clamped to 6..10. */
async function cvHotp(secretBytes, counter, digits, algorithmUri) {
  if (!Number.isInteger(counter)) counter = Math.floor(counter);
  const nDigits = Math.max(6, Math.min(10, digits || 6));
  const { alg } = cvTotpAlgorithm(algorithmUri);

  // 8-byte unsigned big-endian counter (Long semantics like the JVM).
  const message = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    message[i] = c % 0x100;          // JS % on doubles keeps the value non-negative here
    c = Math.floor(c / 0x100);
  }

  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: alg }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));

  const offset = digest[digest.length - 1] & 0x0F;
  const binary =
    ((digest[offset] & 0x7F) << 24) |
    ((digest[offset + 1] & 0xFF) << 16) |
    ((digest[offset + 2] & 0xFF) << 8) |
    (digest[offset + 3] & 0xFF);

  let modulus = 1;
  for (let i = 0; i < nDigits; i++) modulus *= 10;
  return String(binary % modulus).padStart(nDigits, "0");
}

/** TOTP at unix seconds; mirrors app period/digits defaults. */
async function cvTotp(secretBytes, atSeconds, digits, periodSeconds, algorithmUri) {
  const period = Math.max(1, periodSeconds || 30);
  return cvHotp(secretBytes, Math.floor(atSeconds / period), digits, algorithmUri);
}

/** Whole seconds left in the current period (for the countdown). */
function cvTotpRemaining(atSeconds, periodSeconds) {
  const period = Math.max(1, periodSeconds || 30);
  return period - (((atSeconds % period) + period) % period);
}
