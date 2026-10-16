package com.sellerbot.ciphervault.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.URL
import java.net.HttpURLConnection
import java.security.MessageDigest

/**
 * Have I Been Pwned k-anonymity breach checking (https://haveibeenpwned.com/API/v3).
 *
 * The API works by sending the first 5 hex characters of a SHA-1 hash of the
 * password. The server responds with a list of suffixes and counts. We check
 * locally if our full hash is in that list. The password itself never leaves
 * the device.
 *
 * This is an explicit user action (Settings → Check passwords), not automatic,
 * because it requires a network call to an external service.
 */
object Hibp {

    private const val API_BASE = "https://api.pwnedpasswords.com/range/"

    /** Result of a breach check. */
    sealed class Result {
        data class Breached(val count: Int) : Result()
        data object Safe : Result()
        data class Error(val message: String) : Result()
    }

    /**
     * Check if [password] has appeared in known breaches.
     *
     * Runs on IO thread. Returns [Result.Breached] with the number of times
     * the password was seen, [Result.Safe] if not found, or [Result.Error]
     * on network/parse failure.
     */
    suspend fun check(password: CharArray): Result = withContext(Dispatchers.IO) {
        val sha1 = MessageDigest.getInstance("SHA-1")
            .digest(String(password).toByteArray(Charsets.UTF_8))
        val hex = sha1.joinToString(separator = "") { "%02x".format(it) }.uppercase()
        val prefix = hex.substring(0, 5)
        val suffix = hex.substring(5)

        try {
            val url = URL(API_BASE + prefix)
            val connection = url.openConnection() as HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.addRequestProperty("User-Agent", "CipherVault/1.0")
            connection.addRequestProperty("Accept", "text/plain")

            val responseCode = connection.responseCode
            if (responseCode != 200) {
                Result.Error("HIBP API returned $responseCode")
            } else {
                val input = connection.inputStream.bufferedReader().use { it.readText() }
                var found = false
                var count = 0
                input.lineSequence().forEach { line ->
                    val parts = line.split(':')
                    if (parts.size == 2 && parts[0] == suffix) {
                        found = true
                        count = parts[1].toIntOrNull() ?: 0
                    }
                }
                if (found) Result.Breached(count) else Result.Safe
            }
        } catch (e: Exception) {
            Result.Error(e.message ?: "Network error")
        }
    }

    /**
     * Check multiple passwords in parallel.
     */
    suspend fun checkAll(passwords: List<CharArray>): Map<CharArray, Result> = withContext(Dispatchers.IO) {
        passwords.associateWith { check(it) }
    }
}