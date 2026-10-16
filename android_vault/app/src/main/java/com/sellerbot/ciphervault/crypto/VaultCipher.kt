package com.sellerbot.ciphervault.crypto

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM for the vault blob. Authenticated encryption, so tampering with
 * the ciphertext (even one flipped bit) fails loudly instead of silently
 * producing garbage that then gets re-encrypted and synced back.
 *
 * Blob layout — everything the server ever stores:
 *
 * ```
 *   [1 byte version][12 byte IV][ciphertext || 16 byte GCM tag]
 * ```
 *
 * The IV is random per encryption, never reused. The version byte is what
 * lets us change the format later without orphaning existing accounts.
 */
object VaultCipher {

    const val VERSION = 1
    const val KEY_BYTES = 32
    const val IV_BYTES = 12
    const val TAG_BITS = 128
    const val HEADER_BYTES = 1 + IV_BYTES

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val KEY_ALGORITHM = "AES"

    /**
     * @return blob = version || iv || ciphertext+tag
     */
    @Throws(GeneralSecurityException::class)
    fun encrypt(
        plaintext: ByteArray,
        key: ByteArray,
        additionalData: ByteArray = ByteArray(0),
    ): ByteArray {
        require(key.size == KEY_BYTES) { "key must be $KEY_BYTES bytes, was ${key.size}" }

        val iv = ByteArray(IV_BYTES)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, KEY_ALGORITHM),
            GCMParameterSpec(TAG_BITS, iv),
        )
        if (additionalData.isNotEmpty()) {
            cipher.updateAAD(additionalData)
        }
        val ciphertext = cipher.doFinal(plaintext)

        val blob = ByteArray(HEADER_BYTES + ciphertext.size)
        blob[0] = VERSION.toByte()
        iv.copyInto(blob, 1)
        ciphertext.copyInto(blob, HEADER_BYTES)
        return blob
    }

    /**
     * @throws GeneralSecurityException if the blob is malformed, the version
     *         is unsupported, the key is wrong, or the ciphertext was
     *         tampered with. Callers must not swallow this — a wrong key and
     *         a corrupted vault are indistinguishable here, which is the point.
     */
    @Throws(GeneralSecurityException::class)
    fun decrypt(
        blob: ByteArray,
        key: ByteArray,
        additionalData: ByteArray = ByteArray(0),
    ): ByteArray {
        require(key.size == KEY_BYTES) { "key must be $KEY_BYTES bytes, was ${key.size}" }
        if (blob.size < HEADER_BYTES + 16) {
            throw GeneralSecurityException("Vault blob truncated")
        }

        val version = blob[0].toInt() and 0xFF
        if (version != VERSION) {
            throw GeneralSecurityException("Unsupported vault blob version $version")
        }

        val iv = blob.copyOfRange(1, HEADER_BYTES)
        val ciphertext = blob.copyOfRange(HEADER_BYTES, blob.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, KEY_ALGORITHM),
            GCMParameterSpec(TAG_BITS, iv),
        )
        if (additionalData.isNotEmpty()) {
            cipher.updateAAD(additionalData)
        }
        return cipher.doFinal(ciphertext)
    }

    /**
     * Additional authenticated data that binds a blob to its account.
     *
     * Not secret — it is sent alongside the blob — but because it is
     * authenticated, a blob lifted from user A's account cannot be replayed
     * into user B's even if an attacker can write to the API.
     */
    fun accountContext(userId: String, revision: Int): ByteArray =
        "CipherVault/v1/$userId/$revision".toByteArray(Charsets.UTF_8)
}
