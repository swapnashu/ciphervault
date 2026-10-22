/**
 * CipherVault addon crypto — mirrors com.sellerbot.ciphervault byte for byte.
 *
 *   master   = PBKDF2-HMAC-SHA256(password UTF-8, salt, iterations, 32 bytes)
 *   authKey  = HKDF-SHA256(ikm=master, salt=zeros(32), info="CipherVault/auth/v1", 32)
 *   encKey   = HKDF-SHA256(ikm=master, salt=zeros(32), info="CipherVault/enc/v1", 32)
 *   blob     = [version:1][12-byte IV][AES-256-GCM(ciphertext || tag)]
 *   AAD      = "CipherVault/v1/{userId}/{revision}"  — ties blobs to account + revision
 *
 * WebCrypto natively supports HKDF and AES-GCM in every MV3-capable browser
 * (Chromium 88+, Firefox 106+), so no third-party crypto code ships here.
 */

const CWE = new TextEncoder();
const CWE_DEC = new TextDecoder();
const CW_ZERO_SALT = new Uint8Array(32);

function cwB64encode(bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    str += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(str);
}

function cwB64decode(text) {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function cwConcat(...arrays) {
  let len = 0;
  for (const a of arrays) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

/** PBKDF2-SHA256, password encoded as UTF-8 exactly like the Android app/tests. */
async function cvDeriveMaster(password, saltBytes, iterations) {
  if (iterations < 100000) {
    throw new Error("KDF iterations too low");
  }
  const baseKey = await crypto.subtle.importKey(
    "raw", CWE.encode(password), "PBKDF2", false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    baseKey, 256,
  );
  return new Uint8Array(bits);
}

/** HKDF sub-key under the app's canonical "CipherVault/<label>/v1" domain. */
async function cvSubKey(masterBits, label) {
  const key = await crypto.subtle.importKey(
    "raw", masterBits, "HKDF", false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF", hash: "SHA-256",
      salt: CW_ZERO_SALT,
      info: CWE.encode("CipherVault/" + label + "/v1"),
    },
    key, 256,
  );
  return new Uint8Array(bits);
}

async function cvAuthKey(masterBits) { return cvSubKey(masterBits, "auth"); }
async function cvEncKey(masterBits) { return cvSubKey(masterBits, "enc"); }

/** AES-256-GCM, returns the stored blob layout (version, IV, ciphertext||tag). */
async function cvSeal(encKeyBytes, plaintextUtf8, aadUtf8) {
  const key = await crypto.subtle.importKey(
    "raw", encKeyBytes, { name: "AES-GCM" }, false, ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: CWE.encode(aadUtf8), tagLength: 128 },
    key, CWE.encode(plaintextUtf8),
  );
  return cwConcat(Uint8Array.of(1), iv, new Uint8Array(sealed));
}

/** Decrypt the stored blob layout; throws InvalidTag-style errors on mismatch. */
async function cvOpen(encKeyBytes, storedBytes, aadUtf8) {
  if (storedBytes.length < 1 + 12 + 16 || storedBytes[0] !== 1) {
    throw new Error("unexpected blob version");
  }
  const key = await crypto.subtle.importKey(
    "raw", encKeyBytes, { name: "AES-GCM" }, false, ["decrypt"],
  );
  const plain = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: storedBytes.subarray(1, 13),
      additionalData: CWE.encode(aadUtf8),
      tagLength: 128,
    },
    key, storedBytes.subarray(13),
  );
  return CWE_DEC.decode(plain);
}

/** SHA-256 hex digest, e.g. for local login verifiers (not required by server). */
async function cvSha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Short aliases used by background.js / popup.js.
const cvB64encode = cwB64encode;
const cvB64decode = cwB64decode;
