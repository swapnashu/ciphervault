package com.sellerbot.ciphervault.crypto

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

/**
 * RFC 6238 TOTP over RFC 4226 HOTP.
 *
 * This is a direct port of `tools/rfc6238_check.py`, which is verified against
 * every vector in RFC 6238 Appendix B (SHA-1 / SHA-256 / SHA-512). If you change
 * anything here, re-run that script and update the JUnit mirrors in
 * `src/test`.
 *
 * SHA-1 is deprecated for new enrolments: it is cryptographically broken
 * (chosen-prefix collision, 2020). Google Authenticator added SHA-256/512
 * support in 2021. This library defaults to SHA-256 for *new* enrolments and
 * accepts SHA-1 only for legacy QR codes. If a QR code specifies SHA-1 we
 * accept it but warn the user in the UI.
 */
object Totp {

    const val DEFAULT_DIGITS = 6
    const val DEFAULT_PERIOD_SECONDS = 30
    /** Minimum algorithm for new enrolments. */
    val MINIMUM_ALGORITHM = Algorithm.SHA256

    enum class Algorithm(val macName: String, val uriName: String) {
        SHA1("HmacSHA1", "SHA1"),
        SHA256("HmacSHA256", "SHA256"),
        SHA512("HmacSHA512", "SHA512");

        companion object {
            fun fromUri(value: String?): Algorithm =
                entries.firstOrNull { it.uriName.equals(value, ignoreCase = true) } ?: SHA1
        }
    }

    /**
     * RFC 4226 HOTP. Public so the JUnit suite can assert counter-by-counter
     * against the RFC Appendix A vectors directly.
     *
     * @param counter 8-byte big-endian counter, the TOTP time step.
     * @return a [digits]-character zero-padded decimal code.
     */
    @Throws(GeneralSecurityException::class)
    fun hotp(
        secret: ByteArray,
        counter: Long,
        digits: Int = DEFAULT_DIGITS,
        algorithm: Algorithm = Algorithm.SHA1,
    ): String {
        require(digits in 6..10) { "digits must be 6..10, was $digits" }

        val mac = Mac.getInstance(algorithm.macName)
        mac.init(SecretKeySpec(secret, algorithm.macName))

        // ">Q" in Python: unsigned 64-bit, big-endian.
        val message = ByteBuffer.allocate(8).putLong(counter).array()
        val digest = mac.doFinal(message)

        // Dynamic truncation (RFC 4226 section 5.3).
        val offset = digest[digest.size - 1].toInt() and 0x0F
        val binary = ((digest[offset].toInt() and 0x7F) shl 24) or
            ((digest[offset + 1].toInt() and 0xFF) shl 16) or
            ((digest[offset + 2].toInt() and 0xFF) shl 8) or
            (digest[offset + 3].toInt() and 0xFF)

        // Modulo, not a prefix — 6-digit is code % 1_000_000.
        val modulus = 10.pow(digits)
        return (binary % modulus).toString().padStart(digits, '0')
    }

    /**
     * RFC 6238 TOTP at a specific Unix time.
     */
    @Throws(GeneralSecurityException::class)
    fun totp(
        secret: ByteArray,
        atSeconds: Long,
        digits: Int = DEFAULT_DIGITS,
        periodSeconds: Int = DEFAULT_PERIOD_SECONDS,
        algorithm: Algorithm = Algorithm.SHA1,
    ): String {
        require(periodSeconds > 0) { "periodSeconds must be positive" }
        return hotp(secret, floorDiv(atSeconds, periodSeconds.toLong()), digits, algorithm)
    }

    /** Convenience for "now". */
    @Throws(GeneralSecurityException::class)
    fun current(
        secret: ByteArray,
        digits: Int = DEFAULT_DIGITS,
        periodSeconds: Int = DEFAULT_PERIOD_SECONDS,
        algorithm: Algorithm = Algorithm.SHA1,
        clock: () -> Long = System::currentTimeMillis,
    ): String = totp(secret, clock() / 1000, digits, periodSeconds, algorithm)

    /**
     * Whole seconds left in the current period. Drives the countdown ring so
     * the user never copies a code that is about to die.
     */
    fun secondsRemaining(atSeconds: Long, periodSeconds: Int = DEFAULT_PERIOD_SECONDS): Int {
        val elapsed = floorMod(atSeconds, periodSeconds.toLong()).toInt()
        return periodSeconds - elapsed
    }

    /**
     * Current time step, for the countdown progress indicator.
     */
    fun progress(atSeconds: Long, periodSeconds: Int = DEFAULT_PERIOD_SECONDS): Float {
        return secondsRemaining(atSeconds, periodSeconds).toFloat() / periodSeconds
    }

    private fun floorDiv(a: Long, b: Long): Long {
        val q = a / b
        return if ((a % b != 0L) && ((a < 0) != (b < 0))) q - 1 else q
    }

    private fun floorMod(a: Long, b: Long): Long {
        return a - floorDiv(a, b) * b
    }

    private fun Int.pow(exp: Int): Long {
        var result = 1L
        repeat(exp) { result *= this }
        return result
    }
}

/**
 * One 2FA enrolment, as parsed from an `otpauth://totp/...` URI or built for
 * a QR code.
 */
data class TotpEntry(
    val secret: ByteArray,
    val label: String,
    val issuer: String? = null,
    val algorithm: Totp.Algorithm = Totp.MINIMUM_ALGORITHM,
    val digits: Int = Totp.DEFAULT_DIGITS,
    val periodSeconds: Int = Totp.DEFAULT_PERIOD_SECONDS,
) {
    fun code(atSeconds: Long = System.currentTimeMillis() / 1000): String =
        Totp.totp(secret, atSeconds, digits, periodSeconds, algorithm)

    fun secondsRemaining(atSeconds: Long = System.currentTimeMillis() / 1000): Int =
        Totp.secondsRemaining(atSeconds, periodSeconds)

    /** `otpauth://totp/Issuer:label?secret=...&issuer=...` */
    fun toUri(): String {
        val account = listOfNotNull(issuer, label.filter { it != ':' })
            .joinToString(":")
        val query = buildList {
            add("secret=${Base32.encode(secret)}")
            // The issuer belongs in the query as well as the label prefix:
            // importers read it from here, and a label containing a colon
            // cannot carry it unambiguously.
            issuer?.let { add("issuer=${it}") }
            if (algorithm != Totp.Algorithm.SHA1) add("algorithm=${algorithm.uriName}")
            if (digits != Totp.DEFAULT_DIGITS) add("digits=$digits")
            if (periodSeconds != Totp.DEFAULT_PERIOD_SECONDS) add("period=$periodSeconds")
        }.joinToString("&")
        return "otpauth://totp/${urlEncode(account)}?$query"
    }

    // Declared on the class, not in the companion: a data class would
    // otherwise compare `secret` by reference, so two equal enrolments
    // parsed from the same URI would never compare equal.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TotpEntry) return false
        return secret.contentEquals(other.secret) &&
            label == other.label &&
            issuer == other.issuer &&
            algorithm == other.algorithm &&
            digits == other.digits &&
            periodSeconds == other.periodSeconds
    }

    override fun hashCode(): Int {
        var result = secret.contentHashCode()
        result = 31 * result + label.hashCode()
        result = 31 * result + (issuer?.hashCode() ?: 0)
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + digits
        result = 31 * result + periodSeconds
        return result
    }

    companion object {
        /**
         * Parse an `otpauth://totp/...` URI. Accepts the format emitted by
         * Google Authenticator, Authy, Bitwarden and 1Password.
         *
         * Throws [IllegalArgumentException] on anything that is not a
         * well-formed TOTP URI — callers should surface that to the user
         * rather than guess.
         */
        @Throws(IllegalArgumentException::class)
        fun parseUri(uri: String): TotpEntry {
            val trimmed = uri.trim()
            require(trimmed.startsWith("otpauth://", ignoreCase = true)) {
                "Not an otpauth:// URI"
            }

            val parsed = URI(trimmed)
            require(parsed.scheme.equals("otpauth", ignoreCase = true)) {
                "Not an otpauth:// URI"
            }
            require(parsed.host.equals("totp", ignoreCase = true)) {
                "Only otpauth://totp is supported, was otpauth://${parsed.host}"
            }

            val path = parsed.rawPath?.trimStart('/') ?: ""
            require(path.isNotEmpty()) { "Missing account label" }

            val query = parsed.rawQuery.orEmpty()
                .split('&')
                .filter { it.isNotEmpty() }
                .associate { pair ->
                    val idx = pair.indexOf('=')
                    if (idx < 0) pair to ""
                    else pair.substring(0, idx) to pair.substring(idx + 1)
                }

            val secret = query["secret"]
                ?.let { urlDecode(it) }
                ?.let { Base32.decode(it) }
                ?.takeIf { it.isNotEmpty() }
                ?: throw IllegalArgumentException("Missing or empty 'secret' parameter")

            // Issuer may appear as a query param or as the prefix of the label.
            val labelRaw = urlDecode(path)
            val (issuerFromLabel, accountFromLabel) = splitLabel(labelRaw)
            val issuer = query["issuer"]?.let { urlDecode(it) } ?: issuerFromLabel

            return TotpEntry(
                secret = secret,
                label = accountFromLabel,
                issuer = issuer,
                algorithm = Totp.Algorithm.fromUri(query["algorithm"]),
                digits = (query["digits"]?.toIntOrNull() ?: Totp.DEFAULT_DIGITS)
                    .coerceIn(6, 10),
                periodSeconds = (query["period"]?.toIntOrNull()
                    ?: Totp.DEFAULT_PERIOD_SECONDS).coerceAtLeast(1),
            )
        }

        private fun splitLabel(label: String): Pair<String?, String> {
            val idx = label.indexOf(':')
            return if (idx in 0 until label.length - 1) {
                label.substring(0, idx).trim() to label.substring(idx + 1).trim()
            } else {
                null to label.trim()
            }
        }

        private fun urlEncode(value: String): String =
            URLEncoder.encode(value, "UTF-8").replace("+", "%20")
                // Both are legal unencoded in a path (RFC 3986 `pchar`), and
                // Google Authenticator emits them that way. Sending %3A means
                // an importer that splits the label on a raw ':' never sees the
                // issuer/account boundary and shows the whole encoded blob as
                // the account name.
                .replace("%3A", ":")
                .replace("%40", "@")

        private fun urlDecode(value: String): String =
            URLDecoder.decode(value, "UTF-8")
    }
}

private fun abs(value: Long): Long = if (value < 0) -value else value
