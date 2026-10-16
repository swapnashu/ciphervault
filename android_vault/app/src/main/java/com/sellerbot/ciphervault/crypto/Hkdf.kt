package com.sellerbot.ciphervault.crypto

import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF (RFC 5869) over HMAC-SHA256.
 *
 * This is the load-bearing piece of the zero-knowledge design. A single
 * [masterKey] derived from the password is expanded into two independent
 * sub-keys:
 *
 * ```
 *   masterKey ──HKDF(info="auth")──► authSecret  (sent to server at login)
 *              └─HKDF(info="enc")──► encKey      (never leaves the device)
 * ```
 *
 * Knowing `authSecret` does not reveal `encKey`: HKDF-Expand is one-way and
 * the two labels never overlap. So a full server compromise still cannot
 * decrypt anyone's vault — only an offline attack against a stolen
 * `authSecret`, which is exactly why the KDF iteration count matters.
 */
object Hkdf {

    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val HASH_LEN = 32

    /** Maximum okm length for SHA-256 is 255 * 32 = 8160 bytes. */
    const val MAX_OUTPUT_LEN = 255 * HASH_LEN

    /**
     * HKDF-Extract: concentrate the input keying material into a
     * pseudorandom key.
     *
     * @param salt non-secret, may be empty (a zero-filled salt of hash length
     *             is then used, per the RFC).
     */
    @Throws(GeneralSecurityException::class)
    fun extract(salt: ByteArray, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt.isEmpty()) ByteArray(HASH_LEN) else salt
        return hmac(effectiveSalt, ikm)
    }

    /**
     * HKDF-Expand: derive [length] bytes from [prk] bound to [info].
     *
     * @param info context/application separation. Different labels MUST be
     *             used for different sub-keys, or they collide.
     */
    @Throws(GeneralSecurityException::class)
    fun expand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length > 0) { "length must be positive" }
        require(length <= MAX_OUTPUT_LEN) {
            "length $length exceeds HKDF-SHA256 maximum of $MAX_OUTPUT_LEN"
        }

        val blocks = (length + HASH_LEN - 1) / HASH_LEN
        val okm = ByteArray(blocks * HASH_LEN)

        var previous = ByteArray(0)
        for (block in 1..blocks) {
            val input = ByteArray(previous.size + info.size + 1)
            previous.copyInto(input, 0)
            info.copyInto(input, previous.size)
            input[input.size - 1] = block.toByte()

            val output = hmac(prk, input)
            output.copyInto(okm, (block - 1) * HASH_LEN)
            previous = output
        }

        return okm.copyOf(length)
    }

    /**
     * Extract-then-expand in one call.
     */
    @Throws(GeneralSecurityException::class)
    fun derive(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        return expand(extract(salt, ikm), info, length)
    }

    /**
     * Derive a named sub-key of [length] bytes. The label strings below are
     * the canonical domain separators for this app — do not change them
     * without a vault migration, because existing vaults are bound to them.
     */
    @Throws(GeneralSecurityException::class)
    fun subKey(masterKey: ByteArray, label: String, length: Int = 32): ByteArray {
        return derive(
            ikm = masterKey,
            salt = ByteArray(0),
            info = "CipherVault/$label/v1".toByteArray(Charsets.UTF_8),
            length = length,
        )
    }

    /** Sub-key used to authenticate to the server. */
    @Throws(GeneralSecurityException::class)
    fun authKey(masterKey: ByteArray): ByteArray = subKey(masterKey, "auth", HASH_LEN)

    /** Sub-key that encrypts the vault blob. Never transmitted. */
    @Throws(GeneralSecurityException::class)
    fun encryptionKey(masterKey: ByteArray): ByteArray = subKey(masterKey, "enc", 32)

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        return mac.doFinal(message)
    }
}
