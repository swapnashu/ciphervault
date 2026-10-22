/**
 * Shared host-matching helpers (background + popup).
 * Mirrors the app's registrable-domain matching closely enough for login fill:
 * `accounts.example.com` and `example.com` share a domain; `evil-example.com`
 * does not.
 */

const CV_MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
  "com.au", "co.jp", "co.in", "com.br", "co.nz", "com.mx", "com.tr",
  "com.cn", "com.hk", "com.sg", "co.kr", "co.za", "com.ar", "com.il",
  "com.my", "co.th", "com.ph", "com.tw", "com.es", "com.pt",
]);

function cvRegistrableDomain(value) {
  if (!value) return "";
  let host;
  try {
    host = new URL(value).hostname || "";
  } catch {
    return "";
  }
  if (!host) return "";
  host = host.toLowerCase().replace(/\.+$/, "").replace(/^www\./, "");
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const last2 = labels.slice(-2).join(".");
  const last3 = labels.slice(-3).join(".");
  return CV_MULTI_LABEL_SUFFIXES.has(last2) ? last3 : last2;
}

function cvSameDomain(a, b) {
  const da = cvRegistrableDomain(a);
  const db = cvRegistrableDomain(b);
  return !!da && da === db;
}
