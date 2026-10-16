package com.sellerbot.ciphervault.security

import android.os.Build
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.sellerbot.ciphervault.repo.CredentialStore

/**
 * Bridges `BiometricPrompt` to the Keystore-wrapped vault key.
 *
 * Design constraint that shapes everything here: the wrapped key can only be
 * unwrapped *inside* the `onAuthenticationSucceeded` callback, because that is
 * the only window in which the Keystore key is usable. The raw key therefore
 * never exists anywhere the user (or another app) could read it.
 *
 * `BIOMETRIC_STRONG` by default. A 2D camera face unlock that registers as
 * Class 1 or Class 2 will not satisfy it, and this class reports that
 * honestly so the caller falls back to the master password rather than
 * downgrading silently.
 *
 * A user may opt into weaker authenticators from Settings. That is a real
 * trade — some Class 2 face unlocks are fooled by a photograph — so it is
 * explicit, it is off by default, and the Keystore key is regenerated at the
 * weaker strength so the two halves cannot disagree.
 */
class BiometricGate(
    private val activity: FragmentActivity,
    private val keystore: KeystoreManager,
    private val credentials: CredentialStore,
    private val allowWeakBiometrics: Boolean = false,
) {

    /** Track failed biometric attempts for rate limiting. */
    private var failedAttempts = 0

    /** Authenticators this gate will accept, mirrored into the Keystore key. */
    private fun allowedAuthenticators(): Int {
        val strong = BiometricManager.Authenticators.BIOMETRIC_STRONG
        return if (allowWeakBiometrics) {
            // Combined form requires API 30; below that the platform only
            // understands the single-authenticator constants.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                strong or BiometricManager.Authenticators.BIOMETRIC_WEAK
            } else {
                strong
            }
        } else {
            strong
        }
    }

    interface Callback {
        /** The vault encryption key, unwrapped and ready to install. */
        fun onUnlocked(key: ByteArray)

        /** Anything that stopped the flow; safe to show or ignore. */
        fun onFailed(message: String)

        /** User dismissed the prompt. Not an error. */
        fun onCancelled() {}
    }

    /** True when this device can satisfy [allowedAuthenticators]. */
    fun canAuthenticate(): Boolean {
        val manager = BiometricManager.from(activity)
        return manager.canAuthenticate(allowedAuthenticators()) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    // ---- Unlock ------------------------------------------------------------

    /**
     * Prompt and, on success, unwrap the stored key.
     *
     * @param callback where the unwrapped key is delivered; it is the caller's
     *        responsibility to install it and then drop the reference.
     */
    fun authenticate(callback: Callback) {
        if (!canAuthenticate()) {
            callback.onFailed("No strong biometric is available on this device")
            return
        }

        // Rate limit: after MAX_BIOMETRIC_ATTEMPTS failures, require master password
        if (failedAttempts >= MAX_BIOMETRIC_ATTEMPTS) {
            callback.onFailed("Too many failed biometric attempts. Use master password.")
            return
        }

        val stored = credentials.wrappedVaultKeyBase64
        if (stored.isNullOrBlank()) {
            callback.onFailed("Biometric unlock is not set up")
            return
        }

        // Read the IV up front: the strong path has to build its CryptoObject
        // before the prompt can appear, and a blob we cannot parse is one we
        // can never open — better to say so than to fail after a scan.
        val parts = try {
            val blob = android.util.Base64.decode(stored, android.util.Base64.DEFAULT)
            keystore.splitWrapped(blob)
        } catch (e: Exception) {
            Log.e(TAG, "stored wrapped key is unreadable", e)
            credentials.wrappedVaultKeyBase64 = null
            callback.onFailed("Biometric unlock needs to be set up again")
            return
        }
        val iv = parts.first
        val sealed = parts.second

        // A CryptoObject cannot be paired with Class 2 (weak) biometrics —
        // androidx rejects the combination with an IllegalArgumentException,
        // which used to crash the app the moment "Allow face unlock" was on.
        // When weak authenticators are allowed the prompt is therefore
        // non-cryptographic and the cipher is built after the scan, which is
        // also the only moment a fresh auth token exists for a key carrying
        // a validity window.
        val cipher = if (allowWeakBiometrics) {
            null
        } else {
            try {
                keystore.decryptCipher(iv)
            } catch (e: Exception) {
                // Key invalidated: a fingerprint or face was enrolled or removed
                // since enrolment. Correct behaviour is to require the password.
                Log.e(TAG, "decryptCipher failed", e)
                credentials.wrappedVaultKeyBase64 = null
                callback.onFailed("Biometric unlock needs to be set up again")
                return
            }
        }

        val prompt = buildPrompt(
            callback = callback,
            requireCryptoObject = cipher != null,
            onSucceeded = { result ->
                // runCatching rather than try/catch + return: an early return
                // from inside this nested lambda would be a non-local return,
                // which Kotlin only permits through an inline function.
                val outcome = runCatching {
                    val opCipher = cipher
                        ?: result.cryptoObject?.cipher
                        ?: keystore.decryptCipher(iv)
                    keystore.decryptWith(opCipher, sealed)
                }
                outcome.fold(
                    onSuccess = { key -> callback.onUnlocked(key) },
                    onFailure = { e ->
                        // Wrong bytes or a key invalidated since enrolment.
                        Log.e(TAG, "decryptWith failed", e)
                        credentials.wrappedVaultKeyBase64 = null
                        callback.onFailed("Biometric unlock needs to be set up again")
                    },
                )
            },
        )

        if (cipher != null) {
            prompt.authenticate(buildInfo(), BiometricPrompt.CryptoObject(cipher))
        } else {
            prompt.authenticate(buildInfo())
        }
    }

    // ---- Enrolment ---------------------------------------------------------

    /**
     * Wrap [encKey] so future unlocks can use a biometric.
     *
     * Requires its own prompt: the Keystore key is authentication-gated, so
     * the very first wrap must also be authorised by a live scan. That is
     * intentional — otherwise enrolling a finger could be done by anyone who
     * briefly held an unlocked phone.
     */
    fun enroll(encKey: ByteArray, callback: Callback) {
        if (!canAuthenticate()) {
            callback.onFailed("No strong biometric is available on this device")
            return
        }

        // Regenerate so a stale key from a previous enrolment is discarded —
        // and so the key is authorised for exactly the authenticators this
        // gate now accepts. A key minted at STRONG cannot later be opened by
        // a face that only reaches WEAK, and vice versa.
        //
        // Strong path: authenticate on every use. A key carrying a validity
        // window makes Cipher.init() demand an auth token before BiometricPrompt
        // can be shown, and on first enrolment no token exists yet — so setup
        // failed with KEY_USER_NOT_AUTHENTICATED. With timeout 0 init succeeds
        // and the prompt itself gates the operation.
        //
        // Weak path: androidx refuses a CryptoObject alongside Class 2
        // authenticators, so there is no CryptoObject to gate the operation.
        // The key keeps a validity window instead and the cipher is created
        // after a successful scan — the moment a fresh auth token exists.
        val useCryptoObject = !allowWeakBiometrics
        try {
            keystore.createBiometricKey(
                requireBiometricOnEveryUse = useCryptoObject,
                allowWeakBiometrics = allowWeakBiometrics,
            )
        } catch (e: Exception) {
            Log.e(TAG, "createBiometricKey failed", e)
            callback.onFailed("Could not set up biometric unlock")
            return
        }

        val cipher = if (useCryptoObject) {
            try {
                keystore.encryptCipher()
            } catch (e: Exception) {
                Log.e(TAG, "encryptCipher failed", e)
                callback.onFailed("Could not set up biometric unlock")
                return
            }
        } else {
            null
        }

        val prompt = buildPrompt(
            callback = callback,
            requireCryptoObject = useCryptoObject,
            onSucceeded = { result ->
                val outcome = runCatching {
                    val opCipher = cipher
                        ?: result.cryptoObject?.cipher
                        ?: keystore.encryptCipher()
                    keystore.wrapKey(opCipher, encKey)
                }
                outcome.fold(
                    onSuccess = { wrapped ->
                        credentials.wrappedVaultKeyBase64 = android.util.Base64.encodeToString(
                            wrapped,
                            android.util.Base64.NO_WRAP,
                        )
                        callback.onUnlocked(encKey)
                    },
                    onFailure = { e ->
                        Log.e(TAG, "wrapKey failed", e)
                        callback.onFailed("Could not set up biometric unlock")
                    },
                )
            },
        )

        if (cipher != null) {
            prompt.authenticate(buildInfo(), BiometricPrompt.CryptoObject(cipher))
        } else {
            prompt.authenticate(buildInfo())
        }
    }

    /** Remove the wrapped key so biometric unlock stops being offered. */
    fun clear() {
        credentials.wrappedVaultKeyBase64 = null
        try {
            keystore.deleteBiometricKey()
        } catch (_: Exception) {
            // Deleting a key that is already gone is not an error worth
            // surfacing; the wrapped blob is the thing that gates the UI.
        }
    }

    // ---- Internals ---------------------------------------------------------

    private fun buildInfo(): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your vault")
            .setSubtitle("Confirm it's you")
            // Neither BIOMETRIC_STRONG nor BIOMETRIC_WEAK can be combined with
            // DEVICE_CREDENTIAL, so a negative button is mandatory rather than
            // optional here.
            .setNegativeButtonText("Use password")
            .setAllowedAuthenticators(allowedAuthenticators())
            // With this off, merely *presenting* a face or finger unlocks the
            // vault with no deliberate action — enough to open it while the
            // owner is asleep or the phone is taken. An explicit confirm
            // costs one tap and is the right default for a vault.
            .setConfirmationRequired(true)
            .build()

    private fun buildPrompt(
        callback: Callback,
        requireCryptoObject: Boolean,
        onSucceeded: (BiometricPrompt.AuthenticationResult) -> Unit,
    ): BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(activity)

        return BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult,
                ) {
                    // Reset failed attempts on successful authentication
                    failedAttempts = 0
                    if (requireCryptoObject && result.cryptoObject?.cipher == null) {
                        // Can only happen if the prompt was built without a
                        // CryptoObject, which this class never does.
                        callback.onFailed("Biometric unlock failed")
                        return
                    }
                    onSucceeded(result)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // USER_CANCELED / NEGATIVE_BUTTON are deliberate exits,
                    // not failures — the user should land on password entry
                    // without an error message.
                    val benign = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    if (benign) {
                        callback.onCancelled()
                    } else {
                        callback.onFailed(errString.toString())
                    }
                }

                override fun onAuthenticationFailed() {
                    // Finger not recognised yet; the prompt stays open so they
                    // can retry. Do not tear down the UI here.
                    failedAttempts++
                    if (failedAttempts >= MAX_BIOMETRIC_ATTEMPTS) {
                        // Too many failures, cancel the prompt and require password
                        callback.onFailed("Too many failed biometric attempts. Use master password.")
                    }
                }
            },
        )
    }

    companion object {
        private const val TAG = "CipherVault/Biometric"

        /** Maximum failed biometric attempts before requiring master password. */
        private const val MAX_BIOMETRIC_ATTEMPTS = 5

        /** Convenience wrapper matching the ViewModel's lambda style. */
        fun authenticate(
            activity: FragmentActivity,
            keystore: KeystoreManager,
            credentials: CredentialStore,
            allowWeakBiometrics: Boolean = false,
            onSuccess: (ByteArray) -> Unit,
            onFailure: (String) -> Unit,
            onCancelled: () -> Unit = {},
        ) {
            // Captured under a distinct name: inside the anonymous object,
            // `onCancelled()` would be ambiguous with the member being
            // overridden and could resolve to itself.
            val cancelledAction = onCancelled

            BiometricGate(activity, keystore, credentials, allowWeakBiometrics).authenticate(
                object : Callback {
                    override fun onUnlocked(key: ByteArray) = onSuccess(key)
                    override fun onFailed(message: String) = onFailure(message)
                    override fun onCancelled() = cancelledAction()
                },
            )
        }
    }
}
