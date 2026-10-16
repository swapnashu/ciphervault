package com.sellerbot.ciphervault.security

import android.content.Context
import android.content.SharedPreferences

/**
 * Device-local, non-secret preferences.
 *
 * Deliberately *not* [com.sellerbot.ciphervault.repo.CredentialStore]: that
 * one is `EncryptedSharedPreferences`, which pays a Keystore round-trip on
 * every read. These values are toggles and timeouts — there is nothing to
 * protect, and paying that cost would make the settings screen feel broken.
 *
 * Anything that *is* a credential still goes through `CredentialStore`.
 */
class AppSettings(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Let biometrics weaker than Class 3 unlock the vault.
     *
     * Default off because it is a real trade: many camera-based face unlocks
     * register as Class 2, and Class 2 is satisfiable by a photograph on
     * some hardware. A password manager should not quietly make that trade
     * for the user, so it is an explicit switch with a warning attached, and
     * turning it on requires re-enrolling biometric unlock so the Keystore
     * key is regenerated at the weaker strength.
     */
    var allowWeakBiometrics: Boolean
        get() = prefs.getBoolean(KEY_ALLOW_WEAK_BIOMETRICS, false)
        set(value) = prefs.edit().putBoolean(KEY_ALLOW_WEAK_BIOMETRICS, value).apply()

    /**
     * How long a copied secret survives in the clipboard.
     *
     * Seconds, 0 meaning "never clear". Exposed rather than hardcoded
     * because the right answer differs between a phone on a train and a
     * phone on a desk, and users who are not given the choice assume the
     * app simply forgot.
     */
    var clipboardClearSeconds: Int
        get() = prefs.getInt(KEY_CLIPBOARD_CLEAR_SECONDS, DEFAULT_CLIPBOARD_CLEAR_SECONDS)
        set(value) = prefs.edit().putInt(KEY_CLIPBOARD_CLEAR_SECONDS, value).apply()

    companion object {
        /** 20 seconds: a TOTP code is dead by then anyway. */
        const val DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20

        private const val PREFS_NAME = "vault_settings"
        private const val KEY_ALLOW_WEAK_BIOMETRICS = "allow_weak_biometrics"
        private const val KEY_CLIPBOARD_CLEAR_SECONDS = "clipboard_clear_seconds"
    }
}
