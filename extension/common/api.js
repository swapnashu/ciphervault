/**
 * Vault API client for the addon — the same JSON wire the Android app uses,
 * field-for-field. Every failure throws { status, error, message }.
 */

const VAULT_BASE = "https://sellerbots.pythonanywhere.com/vault/api/";

async function cvApi(path, { method = "GET", body = null, token = null } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = "Bearer " + token;
  let resp;
  try {
    resp = await fetch(VAULT_BASE + path, {
      method,
      headers,
      body: body === null ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    throw { status: 0, error: "network", message: "Cannot reach the vault server" };
  }
  const text = await resp.text();
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch { parsed = null; }

  if (!resp.ok) {
    const error = parsed && parsed.error ? parsed.error : "http_" + resp.status;
    let message = parsed && parsed.message ? parsed.message : "Request failed (HTTP " + resp.status + ")";
    if (error === "not_found") {
      // Older server deployments lack the newer routes; scope that to a server
      // version problem the same way the Android app does.
      message = "Not supported by this server yet. Update the server, then try again.";
    }
    if (resp.status === 429) {
      message = parsed && parsed.message ? parsed.message : "Too many attempts. Try again in a few minutes.";
    }
    throw { status: resp.status, error, message };
  }
  return parsed;
}

const CvApi = {
  health: () => cvApi("health"),

  prelogin: (email) => cvApi("prelogin", { method: "POST", body: { email } }),

  login: (email, authKeyB64, device) =>
    cvApi("login", { method: "POST", body: { email, auth_key: authKeyB64, device } }),

  logout: (token) => cvApi("logout", { method: "POST", token }),

  getBlob: (token) => cvApi("blob", { token }),

  putBlob: (token, ciphertextB64, baseRevision) =>
    cvApi("blob", { method: "PUT", token, body: { ciphertext: ciphertextB64, base_revision: baseRevision } }),
};
