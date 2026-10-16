package com.sellerbot.ciphervault.crypto

import java.security.SecureRandom
import java.util.Random
import kotlin.math.log2

/**
 * Random password generation.
 *
 * Two properties matter and both are easy to get subtly wrong:
 *
 * 1. **The source must be [SecureRandom].** A seeded `java.util.Random` is
 *    predictable from a few observed outputs, which would make "generated"
 *    passwords worse than the ones users pick themselves.
 * 2. **Every enabled character class must actually appear.** Naively drawing
 *    `length` characters from a combined pool leaves a real chance of a
 *    "letters and digits" password containing no digits at all. We seed one
 *    character per class first, then fill, then shuffle.
 *
 * The shuffle is what makes step 1 safe: without it the seeded class
 * characters would always sit at the first few positions, telling an
 * attacker which characters to expect and where.
 */
object PasswordGenerator {

    const val DEFAULT_LENGTH = 20
    const val MIN_LENGTH = 6
    const val MAX_LENGTH = 128

    // Full pools. `excludeAmbiguous` trims these rather than the pools being
    // permanently short, so a user who wants maximum entropy can opt back in.
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{}:;,.?/<>~"

    /** Characters people routinely transcribe wrong when reading aloud. */
    private const val AMBIGUOUS = "0O1lI"

    data class Config(
        val length: Int = DEFAULT_LENGTH,
        val lower: Boolean = true,
        val upper: Boolean = true,
        val digits: Boolean = true,
        val symbols: Boolean = true,
        val excludeAmbiguous: Boolean = true,
    ) {
        /** Which pools contribute, in the order they are seeded. */
        fun activeClasses(): List<String> = buildList {
            // Named `offer`, not `add`: a local `add` would shadow
            // MutableList.add and recurse into itself.
            fun offer(source: String) {
                source.sanitised(excludeAmbiguous)
                    .takeIf { it.isNotEmpty() }
                    ?.let { add(it) }
            }
            if (lower) offer(LOWER)
            if (upper) offer(UPPER)
            if (digits) offer(DIGITS)
            if (symbols) offer(SYMBOLS)
        }

        /** Every character a draw can choose from. */
        fun pool(): String = activeClasses().joinToString("")

        private fun String.sanitised(exclude: Boolean): String =
            if (exclude) filter { it !in AMBIGUOUS } else this
    }

    /**
     * @param random injected for tests; production callers should leave it on
     *        the default so the CSPRNG is used.
     * @throws IllegalArgumentException if [Config.length] is out of range or
     *         no character class is enabled.
     */
    fun generate(config: Config = Config(), random: Random = SecureRandom()): String {
        require(config.length in MIN_LENGTH..MAX_LENGTH) {
            "length must be $MIN_LENGTH..$MAX_LENGTH, was ${config.length}"
        }

        val classes = config.activeClasses()
        require(classes.isNotEmpty()) { "Enable at least one character class" }
        require(config.length >= classes.size) {
            "length must be at least ${classes.size} to include every enabled class"
        }

        val pool = config.pool()

        // Seed one from each class, then fill from the combined pool.
        val chars = ArrayList<Char>(config.length)
        for (cls in classes) {
            chars.add(cls[random.nextInt(cls.length)])
        }
        while (chars.size < config.length) {
            chars.add(pool[random.nextInt(pool.length)])
        }

        // Fisher-Yates over the whole result.
        for (i in chars.size - 1 downTo 1) {
            val j = random.nextInt(i + 1)
            val tmp = chars[i]
            chars[i] = chars[j]
            chars[j] = tmp
        }

        return chars.joinToString(separator = "")
    }

    /**
     * A numeric PIN. Unlike [generate] this keeps 0 and 1: PINs are entered
     * on keypads where excluding them costs entropy without any transcription
     * benefit, and the "ambiguous" concern is about reading a *long* password
     * aloud, not thumbing six digits.
     */
    fun pin(length: Int = 6, random: Random = SecureRandom()): String {
        require(length in 1..32) { "PIN length must be 1..32, was $length" }
        return buildString(length) {
            repeat(length) { append(DIGITS[random.nextInt(DIGITS.length)]) }
        }
    }

    /**
     * Shannon entropy of the pool, in bits, before the per-class seeding
     * constraint. Reported to the user so "length 40" is accompanied by a
     * number they can actually compare.
     */
    fun entropyBits(config: Config = Config()): Double {
        val poolSize = config.pool().length
        if (poolSize < 2) return 0.0
        return config.length * log2(poolSize.toDouble())
    }
}
