package com.sellerbot.ciphervault.repo

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Device-local storage for everything needed to log back in without the user
 * re-typing their password.
 *
 * What is stored here: session token, account id, KDF salt and iteration
 * count, and the `sha256(authKey)` verifier. The KDF salt is public (the
 * server sends it anyway), the session token is a credential, the verifier is
 * a one-way check that cannot be reversed into either sub-key, and the vault
 * ciphertext itself lives only in [com.sellerbot.ciphervault.model.Vault] in
 * memory or on the server.
 *
 * What must never be stored here: the master password, the master key, the
 * `authKey` itself, or the HKDF `enc` sub-key. Holding any of those would make
 * the Keystore/biometric gate pointless, because the data would be
 * decryptable without authentication.
 */
interface CredentialStore {
    var userEmail: String?
    var userId: String?
    var sessionToken: String?
    var kdfSaltBase64: String?
    var kdfIterations: Int
    var kdfAlgorithm: String?
    var kdfMemoryKib: Int
    var kdfParallelism: Int
    var localRevision: Int

    /**
     * Hex of `sha256(authKey)` — the same verifier the server keeps.
     *
     * This is what lets `unlock()` reject a wrong password without a network
     * round trip. It is not a credential: a 256-bit HKDF output's hash cannot
     * be used to derive `encKey` or to authenticate, because the server needs
     * the pre-image and the client compares only to decide "was this the right
     * password". Reversing it would mean reversing SHA-256.
     *
     * Absent on installs that predate it; those unlock against the server
     * once and then store it.
     */
    var authKeyVerifierHex: String?

    /**
     * Set when the local KDF copy is known to disagree with the server —
     * a `pull()` failed to decrypt the stored blob, which is what another
     * device changing the password or migrating the KDF looks like from
     * here. The next password unlock re-derives from the server's current
     * parameters instead of trusting the local copy.
     *
     * False on a fresh install; only a failed decrypt ever sets it.
     */
    var paramsStale: Boolean

    /**
     * Base64 of the vault encryption key, wrapped by the Android Keystore
     * key that `BiometricPrompt` gates. Safe at rest: unwrapping it requires
     * a successful Class-3 biometric scan inside the prompt's callback.
     *
     * Absent until the user turns biometric unlock on.
     */
    var wrappedVaultKeyBase64: String?

    fun hasSession(): Boolean
    fun clearAll()
}

class EncryptedCredentialStore(context: Context) : CredentialStore {

    private val prefs: SharedPreferences = createPrefs(context)

    override var userEmail: String?
        get() = prefs.getString(KEY_EMAIL, null)
        set(value) = prefs.edit().putString(KEY_EMAIL, value).apply()

    override var userId: String?
        get() = prefs.getString(KEY_USER_ID, null)
        set(value) = prefs.edit().putString(KEY_USER_ID, value).apply()

    override var sessionToken: String?
        get() = prefs.getString(KEY_TOKEN, null)
        set(value) = prefs.edit().putString(KEY_TOKEN, value).apply()

    override var kdfSaltBase64: String?
        get() = prefs.getString(KEY_SALT, null)
        set(value) = prefs.edit().putString(KEY_SALT, value).apply()

    override var kdfIterations: Int
        get() = prefs.getInt(KEY_ITERATIONS, 600_000)
        set(value) = prefs.edit().putInt(KEY_ITERATIONS, value).apply()

    override var kdfAlgorithm: String?
        get() = prefs.getString(KEY_ALGO, null)
        set(value) = prefs.edit().putString(KEY_ALGO, value).apply()

    override var kdfMemoryKib: Int
        get() = prefs.getInt(KEY_MEMORY_KIB, 32 * 1024)
        set(value) = prefs.edit().putInt(KEY_MEMORY_KIB, value).apply()

    override var kdfParallelism: Int
        get() = prefs.getInt(KEY_PARALLELISM, 4)
        set(value) = prefs.edit().putInt(KEY_PARALLELISM, value).apply()

    override var localRevision: Int
        get() = prefs.getInt(KEY_REVISION, 0)
        set(value) = prefs.edit().putInt(KEY_REVISION, value).apply()

    override var wrappedVaultKeyBase64: String?
        get() = prefs.getString(KEY_WRAPPED_KEY, null)
        set(value) = prefs.edit().putString(KEY_WRAPPED_KEY, value).apply()

    override var authKeyVerifierHex: String?
        get() = prefs.getString(KEY_AUTH_VERIFIER, null)
        set(value) = prefs.edit().putString(KEY_AUTH_VERIFIER, value).apply()

    override var paramsStale: Boolean
        get() = prefs.getBoolean(KEY_PARAMS_STALE, false)
        set(value) = prefs.edit().putBoolean(KEY_PARAMS_STALE, value).apply()

    override fun hasSession(): Boolean = !sessionToken.isNullOrBlank()

    override fun clearAll() {
        prefs.edit().clear().apply()
    }

    private companion object {
        const val PREFS_NAME = "vault_credentials"
        const val KEY_EMAIL = "email"
        const val KEY_USER_ID = "user_id"
        const val KEY_TOKEN = "session_token"
        const val KEY_SALT = "kdf_salt"
        const val KEY_ITERATIONS = "kdf_iterations"
        const val KEY_ALGO = "kdf_algo"
        const val KEY_MEMORY_KIB = "kdf_memory_kib"
        const val KEY_PARALLELISM = "kdf_parallelism"
        const val KEY_REVISION = "local_revision"
        const val KEY_WRAPPED_KEY = "wrapped_vault_key"
        const val KEY_AUTH_VERIFIER = "auth_key_verifier"
        const val KEY_PARAMS_STALE = "params_stale"

        fun createPrefs(context: Context): SharedPreferences {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            return EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        }
    }
}
