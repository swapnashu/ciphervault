/**
 * CipherVault content script — fills login forms and detects new logins.
 * Talkative only via messages; it never receives more than one entry.
 */

(() => {
  "use strict";

  /** React/managed-input-safe value assignment. */
  function setNativeValue(input, value) {
    const proto = input instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value");
    if (setter && setter.set) {
      setter.set.call(input, value);
    } else {
      input.value = value;
    }
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function fieldMatches(input, words) {
    const parts = [
      input.name || "", input.id || "", input.autocomplete || "",
      (input.placeholder || "").toLowerCase(),
      input.getAttribute("aria-label") || "",
    ].join(" ").toLowerCase();
    return words.some((w) => parts.includes(w));
  }

  function findLoginFields() {
    const passwords = Array.from(document.querySelectorAll("input[type=password]"))
      .filter((el) => el && !el.disabled && !el.readOnly &&
        el.type === "password" && (el.offsetParent !== null || el.type === "text"));

    const usernameInputs = Array.from(
      document.querySelectorAll('input[type=text], input[type=email], input:not([type])'),
    ).filter((el) => !el.disabled && !el.readOnly && el.offsetParent !== null);

    const user = usernameInputs.find((el) =>
      fieldMatches(el, ["user", "email", "login", "accoun", "handle", "phone", "id"]) ||
      el.type === "email") || null;

    const password = passwords.find((el) =>
      fieldMatches(el, ["password", "passwd", "pass"])) || passwords[0] || null;

    return { username: user, password };
  }

  let cvLastCaptured = 0;

  async function maybeCapture() {
    const now = Date.now();
    if (now - cvLastCaptured < 1500) return;
    const { username, password } = findLoginFields();
    if (!password || !password.value || password.value.length < 4) return;
    if (document.querySelectorAll("input[type=password]:not([type=hidden])").length > 1) {
      // More than one password box looks like sign-up or change-password — skip.
      return;
    }
    const name = username && username.value ? username.value.trim() : "";
    if (!name) return;
    cvLastCaptured = now;
    try {
      await chrome.runtime.sendMessage({
        cmd: "submitDetected",
        username: name,
        password: password.value,
        url: location.href,
        tabId: null,
      });
    } catch { /* extension context invalidated (reload) — ignore */ }
  }

  // Capture on submit and on password-field Enter.
  document.addEventListener("submit", (ev) => {
    if (ev.isTrusted) maybeCapture();
  }, true);

  document.addEventListener("keydown", (ev) => {
    if (ev.isTrusted && ev.key === "Enter") {
      const { username, password } = findLoginFields();
      if (password && document.activeElement === password) {
        maybeCapture();
      }
    }
  }, true);

  // Fill on request from the popup.
  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (!msg || msg.cmd !== "cvFill") return;
    (async () => {
      const fields = findLoginFields();
      let filled = 0;
      if (msg.username && fields.username) {
        setNativeValue(fields.username, msg.username);
        filled++;
      }
      if (msg.password && fields.password) {
        setNativeValue(fields.password, msg.password);
        filled++;
      }
      if (fields.password) {
        try { fields.password.focus({ preventScroll: false }); } catch {}
      }
      respond({ ok: filled > 0, filled });
    })();
    return true;
  });
})();
