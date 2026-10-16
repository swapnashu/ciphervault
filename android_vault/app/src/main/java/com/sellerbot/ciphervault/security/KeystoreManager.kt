package com.sellerbot.ciphervault.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore key management for biometric unlock.
 *
 * How biometric unlock works without ever weakening the master password:
 *
 * ```
 *   encKey ──wrapped with Keystore AES key──► local blob (EncryptedFile / prefs)
 *                         ▲
 *                         │  Keystore key has setUserAuthenticationRequired(true)
 *                         │  so it only decrypts after BIOMETRIC_STRONG succeeds
 *              BiometricPrompt returns a CryptoObject holding it
 * ```
 *
 * The Keystore key never leaves secure hardware, so an attacker who copies
 * the wrapped blob off the phone still cannot open it. And because the key is
 * invalidated when a new fingerprint/face is enrolled, removing a biometric
 * from the device correctly locks the app out of biometric unlock.
 *
 * Face unlock note: the key is generated for [KeyProperties.AUTH_BIOMETRIC_STRONG],
 * which only Class 3 biometrics satisfy. Many 2D camera face unlocks are
 * Class 1/2 and will be rejected — that is the default, and deliberately so.
 * A user who opts in from Settings gets a key authorised for
 * [KeyProperties.AUTH_BIOMETRIC_WEAK] as well, which is what lets face
 * unlock work; the trade is spelled out there rather than assumed here.
 */
class KeystoreManager(
    private val keyStoreName: String = "AndroidKeyStore",
) {

    private val keyStore: KeyStore = KeyStore.getInstance(keyStoreName).apply { load(null) }

    /** True if the device can satisfy a strong biometric at all. */
    fun hasStrongBiometrics(crypto: Cipher? = null): Boolean {
        return try {
            if (keyStore.containsAlias(KEY_ALIAS)) return true
            crypto != null
        } catch (e: GeneralSecurityException) {
            false
        }
    }

    fun keyExists(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    /**
     * Generate (or regenerate) the biometric-gated AES key.
     *
     * @param requireBiometricOnEveryUse if false the key may be used for a
     *        short window after authentication, which is what lets the app
     *        auto-lock on a timeout instead of on every screen.
     * @param allowWeakBiometrics accept Class 2 (and 1) authenticators too —
     *        in practice, camera-based face unlock. Off by default; when on,
     *        the key is authorised for `AUTH_BIOMETRIC_WEAK` as well as
     *        `AUTH_BIOMETRIC_STRONG`. Below API 30 there is no weak-auth
     *        constant, so those devices stay strong-only regardless.
     */
    @Throws(GeneralSecurityException::class)
    fun createBiometricKey(
        requireBiometricOnEveryUse: Boolean = false,
        allowWeakBiometrics: Boolean = false,
    ) {
        deleteBiometricKey()

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            // If a fingerprint or face is removed from the device, this key
            // becomes unusable. That is the correct security behaviour.
            .setInvalidatedByBiometricEnrollment(true)

        val spec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val timeout = if (requireBiometricOnEveryUse) 0 else AUTH_VALIDITY_SECONDS
            val allowed = if (allowWeakBiometrics) {
                KeyProperties.AUTH_BIOMETRIC_STRONG or AUTH_BIOMETRIC_WEAK
            } else {
                KeyProperties.AUTH_BIOMETRIC_STRONG
            }
            builder.setUserAuthenticationParameters(timeout, allowed)
            builder.build()
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(
                if (requireBiometricOnEveryUse) 0 else AUTH_VALIDITY_SECONDS
            )
            @Suppress("DEPRECATION")
            builder.build()
        }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            keyStoreName,
        )
        generator.init(spec)
        generator.generateKey()
    }

    /**
     * A [Cipher] ready to decrypt a wrapped vault key. Passing this into
     * [androidx.biometric.BiometricPrompt.PromptInfo.setCryptoObject] is what
     * forces a successful biometric scan before the key becomes usable.
     *
     * @param iv the exact IV the blob was sealed with. The Keystore mints a
     *        random IV on encrypt and will not accept a user-chosen one while
     *        randomized encryption is on, so the only correct value is the one
     *        stored alongside the ciphertext — assuming a fixed IV here made
     *        every unwrap fail with AEADBadTagException.
     */
    @Throws(GeneralSecurityException::class)
    fun decryptCipher(iv: ByteArray): Cipher {
        val key = getSecretKey()
        return Cipher.getInstance(DECRYPT_TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        }
    }

    /** A [Cipher] ready to wrap the vault key when enabling biometrics. */
    @Throws(GeneralSecurityException::class)
    fun encryptCipher(): Cipher {
        val key = getSecretKey()
        return Cipher.getInstance(ENCRYPT_TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
    }

    /** Reuse a cipher from a successful [androidx.biometric.BiometricPrompt] result. */
    @Throws(GeneralSecurityException::class)
    fun decryptWith(cipher: Cipher, wrappedKey: ByteArray): ByteArray {
        return cipher.doFinal(wrappedKey)
    }

    /**
     * Wrap a freshly derived [encKey] for storage on this device.
     *
     * Returns `IV length || IV || ciphertext` so the IV survives the trip to
     * disk. GCM cannot be decrypted without the exact IV it was sealed with.
     */
    @Throws(GeneralSecurityException::class)
    fun wrapKey(cipher: Cipher, keyToWrap: ByteArray): ByteArray {
        val iv = cipher.iv
            ?: throw GeneralSecurityException("Cipher has no IV to store")
        val sealed = cipher.doFinal(keyToWrap)
        return byteArrayOf(iv.size.toByte()) + iv + sealed
    }

    /**
     * Split a blob produced by [wrapKey] back into its IV and ciphertext.
     *
     * @throws IllegalArgumentException if the blob is malformed or predates
     *         the IV prefix; the caller treats that as "set biometrics up again".
     */
    fun splitWrapped(blob: ByteArray): Pair<ByteArray, ByteArray> {
        require(blob.size >= 2) { "wrapped blob is truncated" }
        val ivLen = blob[0].toInt() and 0xFF
        require(ivLen in MIN_IV_BYTES..MAX_IV_BYTES) { "wrapped blob has no IV prefix" }
        require(blob.size > 1 + ivLen) { "wrapped blob is truncated" }
        return blob.copyOfRange(1, 1 + ivLen) to blob.copyOfRange(1 + ivLen, blob.size)
    }

    @Throws(GeneralSecurityException::class)
    fun deleteBiometricKey() {
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    @Throws(GeneralSecurityException::class)
    private fun getSecretKey(): SecretKey {
        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
            ?: throw GeneralSecurityException("Biometric key not present")
        return entry.secretKey
            ?: throw GeneralSecurityException("Biometric key missing")
    }

    companion object {
        private const val KEY_ALIAS = "ciphervault.biometric.v1"
        private const val DECRYPT_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val ENCRYPT_TRANSFORMATION = "AES/GCM/NoPadding"

        /** GCM IVs are 96 bits by default; accept the wider range JCE permits. */
        private const val MIN_IV_BYTES = 8
        private const val MAX_IV_BYTES = 16

        /**
         * `KeyProperties.AUTH_BIOMETRIC_WEAK`, which the SDK stubs do not
         * expose despite shipping since API 30 — verified against
         * `platforms/android-34/android.jar`, where only
         * `AUTH_BIOMETRIC_STRONG` and `AUTH_DEVICE_CREDENTIAL` appear.
         *
         * The value is from AOSP `KeyProperties.java`, where the weak mask is
         * a superset of the strong one (0x00FF covers 0x000F). Declared here
         * rather than guessed as `0x0F shl 4` so that the number on screen is
         * the number the platform checks.
         */
        private const val AUTH_BIOMETRIC_WEAK = 0x00FF

        /**
         * 15 minutes. After this the Keystore key stops working and the user
         * must re-authenticate biometrically (or with the master password).
         */
        const val AUTH_VALIDITY_SECONDS = 15 * 60
    }
}
