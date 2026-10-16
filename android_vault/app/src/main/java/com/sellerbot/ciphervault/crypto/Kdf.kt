package com.sellerbot.ciphervault.crypto

import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Password → master key.
 *
 * Supports two algorithms:
 *
 * 1. PBKDF2-HMAC-SHA256 — the legacy default. Available in the Android
 *    platform (`javax.crypto`), zero supply-chain surface. 600,000 iterations
 *    is the OWASP 2023 floor. Still secure if the iteration count is high
 *    enough, but GPU-friendly.
 *
 * 2. Argon2id — the modern, memory-hard choice. Added via Bouncy Castle's
 *    pure-Java provider (`bcprov-jdk18on`), so no native libraries are pulled
 *    in. Parameters default to 32 MiB memory, 3 passes, 4 lanes — roughly
 *    1 second on a 2024 flagship, ~2–3 s on a 2020 mid-range. These are the
 *    OWASP 2024 "interactive" recommendations scaled for mobile.
 *
 * Migration is atomic, not additive: the encryption key is an HKDF sibling
 * of the auth verifier under the same master, so changing the KDF changes
 * both. The client re-encrypts the vault under the new parameters and the
 * server commits the new verifier and the new blob in one transaction —
 * committing either alone would lock every device out. Until this account
 * migrates it stays on its stored parameters, and every device keeps
 * reading the vault with them.
 */
object Kdf {

    /**
     * KDF parameters, stored server-side alongside the account so the app can
     * reproduce the key on a new device.
     *
     * For PBKDF2: only [iterations] is used.
     * For Argon2id: [memoryKiB], [parallelism], [iterations] (passes) are used.
     *
     * The floors below are deliberate minimums. Anything lower makes a stolen
     * verifier cheap to grind on commodity hardware, and there is no UX reason
     * to go below them — the defaults are already tuned for sub-second latency.
     */
    data class Params(
        val algorithm: Algorithm = Algorithm.ARGON2ID,
        val iterations: Int = DEFAULT_ARGON2_PASSES, // PBKDF2 rounds or Argon2 passes
        val memoryKiB: Int = DEFAULT_ARGON2_MEMORY_KIB,
        val parallelism: Int = DEFAULT_ARGON2_LANES,
        val saltBytes: Int = SALT_BYTES,
        val keyBits: Int = KEY_BITS,
    ) {
        init {
            when (algorithm) {
                Algorithm.PBKDF2_SHA256 -> {
                    require(iterations >= MIN_PBKDF2_ITERATIONS) {
                        "PBKDF2 iterations $iterations below floor of $MIN_PBKDF2_ITERATIONS"
                    }
                    require(memoryKiB == DEFAULT_ARGON2_MEMORY_KIB) { "memoryKiB is ignored for PBKDF2" }
                    require(parallelism == DEFAULT_ARGON2_LANES) { "parallelism is ignored for PBKDF2" }
                }
                Algorithm.ARGON2ID -> {
                    require(iterations >= MIN_ARGON2_PASSES) {
                        "Argon2id passes $iterations below floor of $MIN_ARGON2_PASSES"
                    }
                    require(memoryKiB >= MIN_ARGON2_MEMORY_KIB) {
                        "Argon2id memory $memoryKiB KiB below floor of $MIN_ARGON2_MEMORY_KIB KiB"
                    }
                    require(parallelism >= MIN_ARGON2_LANES) {
                        "Argon2id parallelism $parallelism below floor of $MIN_ARGON2_LANES"
                    }
                }
            }
            require(saltBytes >= 16) { "salt must be at least 16 bytes" }
            require(keyBits in 128..512) { "keyBits must be 128..512" }
        }

        enum class Algorithm(val uriName: String) {
            PBKDF2_SHA256("PBKDF2WithHmacSHA256"),
            ARGON2ID("argon2id");

            companion object {
                fun fromStored(value: String): Algorithm =
                    entries.firstOrNull { it.name == value }
                        ?: throw IllegalArgumentException("Unknown KDF algorithm '$value'")
            }
        }
    }

    // PBKDF2 constants (legacy)
    const val DEFAULT_ITERATIONS = 600_000
    const val MIN_PBKDF2_ITERATIONS = 100_000

    // Argon2id constants (new default)
    // OWASP 2024 "interactive" baseline: 64 MiB, 3 passes, 4 lanes.
    // Scaled to 32 MiB for mobile RAM pressure; still ~1 s on a flagship.
    const val DEFAULT_ARGON2_MEMORY_KIB = 32 * 1024 // 32 MiB
    const val MIN_ARGON2_MEMORY_KIB = 16 * 1024     // 16 MiB absolute floor
    const val DEFAULT_ARGON2_PASSES = 3
    const val MIN_ARGON2_PASSES = 2
    const val DEFAULT_ARGON2_LANES = 4
    const val MIN_ARGON2_LANES = 1

    // Shared
    const val SALT_BYTES = 16
    const val KEY_BITS = 256

    /** Cryptographically strong salt. Non-secret — it is stored and shipped. */
    fun generateSalt(bytes: Int = SALT_BYTES): ByteArray {
        val salt = ByteArray(bytes)
        SecureRandom().nextBytes(salt)
        return salt
    }

    /**
     * Derive a [params.keyBits]-bit master key from [password] and [salt].
     *
     * @param password the user's master password, as chars not as bytes, so
     *                 PBKDF2's Unicode handling is consistent across devices.
     *                 For Argon2id the chars are UTF-8 encoded.
     */
    @Throws(GeneralSecurityException::class)
    fun derive(password: CharArray, salt: ByteArray, params: Params = Params()): ByteArray {
        require(salt.size >= 16) { "salt must be at least 16 bytes" }

        return when (params.algorithm) {
            Params.Algorithm.PBKDF2_SHA256 -> derivePbkdf2(password, salt, params)
            Params.Algorithm.ARGON2ID -> deriveArgon2id(password, salt, params)
        }
    }

    @Throws(GeneralSecurityException::class)
    private fun derivePbkdf2(password: CharArray, salt: ByteArray, params: Params): ByteArray {
        val spec = PBEKeySpec(password, salt, params.iterations, params.keyBits)
        return try {
            val factory = SecretKeyFactory.getInstance(params.algorithm.uriName)
            factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    @Throws(GeneralSecurityException::class)
    private fun deriveArgon2id(password: CharArray, salt: ByteArray, params: Params): ByteArray {
        val passwordBytes = String(password).toByteArray(Charsets.UTF_8)
        val out = ByteArray(params.keyBits / 8)

        val argon2Params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt)
            .withMemoryAsKB(params.memoryKiB)
            .withIterations(params.iterations)
            .withParallelism(params.parallelism)
            .build()

        val generator = Argon2BytesGenerator()
        generator.init(argon2Params)
        generator.generateBytes(passwordBytes, out)

        // Zero the password bytes we created
        passwordBytes.fill(0)

        return out
    }

    /**
     * Score a password without any network call. Deliberately simple: length
     * plus character-class variety. Real breach checking is a separate,
     * explicit user action against the Have I Been Pwned k-anonymity API,
     * because that has to leave the device.
     */
    fun strength(password: String): Strength {
        if (password.isEmpty()) return Strength.EMPTY

        val classes = listOf(
            password.any { it.isLowerCase() },
            password.any { it.isUpperCase() },
            password.any { it.isDigit() },
            password.any { !it.isLetterOrDigit() },
        ).count { it }

        // Punish repetition: "aaaaaaaaaaaa" is not strong just because it is long.
        val repetitionRatio = password.toSet().size.toFloat() / password.length
        val lengthScore = when {
            password.length >= 20 -> 3
            password.length >= 14 -> 2
            password.length >= 10 -> 1
            else -> 0
        }

        val raw = (lengthScore + classes).toFloat()
        val adjusted = (raw * repetitionRatio).toInt().coerceIn(0, 5)
        return Strength.of(adjusted)
    }

    enum class Strength(val score: Int, val label: String) {
        EMPTY(0, "Empty"),
        VERY_WEAK(1, "Very weak"),
        WEAK(2, "Weak"),
        FAIR(3, "Fair"),
        STRONG(4, "Strong"),
        VERY_STRONG(5, "Very strong");

        companion object {
            fun of(score: Int): Strength = entries.firstOrNull { it.score == score } ?: WEAK
        }
    }
}