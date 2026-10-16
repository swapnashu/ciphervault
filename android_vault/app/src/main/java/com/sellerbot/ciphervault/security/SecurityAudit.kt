package com.sellerbot.ciphervault.security

import com.sellerbot.ciphervault.model.EntryType
import com.sellerbot.ciphervault.model.Vault
import com.sellerbot.ciphervault.model.VaultEntry

/**
 * Password-hygiene audit over the decrypted vault.
 *
 * Pure and synchronous on purpose: it runs in the UI thread over an
 * in-memory list, it never sees the network, and every rule here is unit
 * tested rather than left to be discovered by staring at a red badge.
 *
 * This is *advice*, not enforcement. Nothing is blocked and nothing is
 * changed; the worst outcome of a wrong finding is a row the user ignores.
 */
object SecurityAudit {

    enum class Severity { HIGH, MEDIUM, LOW }

    enum class Kind {
        /** Short, single-class, or a well-known guessable value. */
        WEAK,
        /** The same password guards more than one entry. */
        REUSED,
        /** Unchanged for longer than the rotation threshold. */
        STALE,
        /** A login with a password but no second factor. */
        NO_2FA,
    }

    data class Finding(
        val kind: Kind,
        val severity: Severity,
        val entry: VaultEntry,
        /** Human-readable reason, already phrased for display. */
        val detail: String,
        /** Other entries sharing a reused password; empty for other kinds. */
        val related: List<String> = emptyList(),
    ) {
        val entryId: String get() = entry.id
    }

    data class Report(
        val findings: List<Finding>,
        val totalEntries: Int,
        val loginsWithPassword: Int,
    ) {
        /** 100 is spotless; 0 means every stored password needs attention. */
        val score: Int
            get() {
                if (loginsWithPassword == 0) return 100
                val weighted = findings.sumOf { it.severity.weight }
                val exposure = loginsWithPassword * Severity.HIGH.weight
                return (100 - (100.0 * weighted / exposure).toInt()).coerceIn(0, 100)
            }

        val hasHigh: Boolean get() = findings.any { it.severity == Severity.HIGH }
        fun count(kind: Kind): Int = findings.count { it.kind == kind }
    }

    private val Severity.weight: Int
        get() = when (this) {
            Severity.HIGH -> 3
            Severity.MEDIUM -> 2
            Severity.LOW -> 1
        }

    /**
     * Minimum length before a password counts as adequate.
     *
     * 12 rather than 8: NIST SP 800-63B moved to length-first guidance, and
     * an 8-character maximum is what produced the hashcat-solvable era of
     * "P@ssw0rd!".
     */
    const val MIN_LENGTH = 12

    /** How long a password may go unchanged before it is flagged. */
    const val STALE_AFTER_DAYS = 365L

    /**
     * Substrings that make a password trivially guessable no matter how
     * long it is. Deliberately small — this is a tripwire for the obvious
     * cases, not a dictionary attack simulator.
     */
    private val FRAGMENTS = listOf(
        "password", "passw0rd", "qwerty", "letmein", "welcome",
        "iloveyou", "admin", "123456", "111111", "abc123",
        "monkey", "dragon", "football", "baseball", "sunshine",
        "princess", "trustno1", "superman", "starwars", "whatever",
    )

    fun audit(
        vault: Vault,
        now: Long = System.currentTimeMillis(),
        staleAfterDays: Long = STALE_AFTER_DAYS,
    ): Report {
        val findings = mutableListOf<Finding>()

        // Only logins. `VaultEntry.password` exists on every type, but a
        // password stuffed into a note or a card's memo field is not a
        // credential and auditing it would bury the findings that matter.
        val logins = vault.liveEntries.filter {
            it.type == EntryType.LOGIN && it.password?.isNotBlank() == true
        }

        // --- Reused -------------------------------------------------------
        // Computed first so a reused password is not reported twice, once as
        // reused and again as weak, for the same string.
        val byPassword = logins.groupBy { it.password!! }.filterValues { it.size > 1 }
        val reusedIds = mutableSetOf<String>()
        for ((_, group) in byPassword) {
            for (entry in group) {
                reusedIds += entry.id
                findings += Finding(
                    kind = Kind.REUSED,
                    severity = if (group.size > 2) Severity.HIGH else Severity.MEDIUM,
                    entry = entry,
                    detail = "This password also guards ${group.size - 1} other " +
                        if (group.size - 1 == 1) "account" else "accounts",
                    // Everyone *else* on this password. Listing the entry
                    // itself here would read as "this password also guards
                    // GitHub" on GitHub's own row.
                    related = group.filter { it.id != entry.id }.map { it.title },
                )
            }
        }

        // --- Weak ---------------------------------------------------------
        for (entry in logins) {
            val password = entry.password!!
            if (entry.id in reusedIds) continue

            val reason = weakReason(password) ?: continue
            findings += Finding(
                kind = Kind.WEAK,
                severity = severityFor(password),
                entry = entry,
                detail = reason,
            )
        }

        // --- Stale --------------------------------------------------------
        for (entry in logins) {
            val stamped = entry.passwordUpdatedAt ?: entry.updatedAt
            val ageDays = (now - stamped) / Vault.MILLIS_PER_DAY
            if (ageDays <= staleAfterDays) continue
            findings += Finding(
                kind = Kind.STALE,
                severity = if (ageDays > staleAfterDays * 2) Severity.MEDIUM else Severity.LOW,
                entry = entry,
                detail = "Last changed $ageDays days ago",
            )
        }

        // --- No second factor ---------------------------------------------
        for (entry in logins) {
            if (entry.hasTotp()) continue
            findings += Finding(
                kind = Kind.NO_2FA,
                severity = Severity.LOW,
                entry = entry,
                detail = "No two-factor code is stored for this login",
            )
        }

        return Report(
            findings = findings.sortedWith(
                compareBy({ it.severity.ordinal }, { it.entry.title.lowercase() }),
            ),
            totalEntries = vault.liveEntries.size,
            loginsWithPassword = logins.size,
        )
    }

    /**
     * Why a password is weak, or null when it is not.
     *
     * Ordered from the most certain signal outward so the message the user
     * sees names the actual problem rather than a generic "too short".
     */
    fun weakReason(password: String): String? {
        val lower = password.lowercase()
        if (FRAGMENTS.any { it in lower }) {
            return "Contains a word that appears on every password-guessing list"
        }
        if (password.length < MIN_LENGTH) {
            return "Only ${password.length} characters — aim for $MIN_LENGTH or more"
        }
        if (distinctClasses(password) == 1) {
            return "Uses a single character type, so it can be guessed far faster"
        }
        if (isRepeatedOrSequential(password)) {
            return "Built from a repeating or running pattern"
        }
        return null
    }

    private fun severityFor(password: String): Severity = when {
        password.length < 8 -> Severity.HIGH
        password.length < MIN_LENGTH -> Severity.MEDIUM
        else -> Severity.LOW
    }

    /** 1 = one class (all digits, all letters, ...), 4 = upper+lower+digit+symbol. */
    private fun distinctClasses(password: String): Int {
        var classes = 0
        if (password.any { it.isLowerCase() }) classes++
        if (password.any { it.isUpperCase() }) classes++
        if (password.any { it.isDigit() }) classes++
        if (password.any { !it.isLetterOrDigit() }) classes++
        return classes
    }

    /**
     * `aaaaaa`, `123456`, `qwerty`, `abcdabcd`.
     *
     * Checked as runs of length 4 or more, which catches the patterns people
     * actually type without flagging a password that merely contains "abc".
     */
    private fun isRepeatedOrSequential(password: String): Boolean {
        val chars = password.lowercase()
        if (chars.length < 4) return false

        for (i in 0..chars.length - 4) {
            val window = chars.substring(i, i + 4)
            if (window.toSet().size == 1) return true

            val codes = window.map { it.code }
            val ascending = codes.zipWithNext().all { (a, b) -> b - a == 1 }
            val descending = codes.zipWithNext().all { (a, b) -> a - b == 1 }
            if (ascending || descending) return true
        }
        return false
    }
}
