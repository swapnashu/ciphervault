package com.sellerbot.ciphervault.crypto

/**
 * RFC 4648 Base32, as used by every `otpauth://` URI in the wild.
 *
 * No third-party dependency on purpose — this sits in the key path for 2FA
 * enrolment and needs to be auditable in one screen.
 */
object Base32 {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** Decode table: -1 = invalid character, ignored by callers that filter first. */
    private val LOOKUP = IntArray(128) { -1 }.also { table ->
        ALPHABET.forEachIndexed { index, char ->
            table[char.code] = index
            // Accept lowercase too; some exporters emit it.
            table[char.lowercaseChar().code] = index
        }
    }

    /**
     * Decode a Base32 string. Padding `=` is optional, whitespace is stripped,
     * case is irrelevant. Throws [IllegalArgumentException] on invalid input.
     */
    fun decode(input: String): ByteArray {
        val cleaned = input.filter { !it.isWhitespace() && it != '=' }
        if (cleaned.isEmpty()) return ByteArray(0)

        // Every 8 Base32 characters carry exactly 5 bytes.
        val out = ByteArray(cleaned.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        var index = 0

        for (char in cleaned) {
            val value = if (char.code < 128) LOOKUP[char.code] else -1
            if (value == -1) throw IllegalArgumentException("Invalid Base32 character: '$char'")

            buffer = (buffer shl 5) or value
            bitsLeft += 5

            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out[index++] = ((buffer shr bitsLeft) and 0xFF).toByte()
            }
        }

        // Reject truncated output that would silently drop bits.
        if (bitsLeft > 0 && bitsLeft >= 5) {
            throw IllegalArgumentException("Invalid Base32 length")
        }

        return if (index == out.size) out else out.copyOf(index)
    }

    /**
     * Encode bytes to unpadded Base32. Used for the enrolment QR round-trip.
     */
    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""

        val out = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0

        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8

            while (bitsLeft >= 5) {
                bitsLeft -= 5
                out.append(ALPHABET[(buffer shr bitsLeft) and 0x1F])
            }
        }

        if (bitsLeft > 0) {
            out.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1F])
        }

        return out.toString()
    }
}
