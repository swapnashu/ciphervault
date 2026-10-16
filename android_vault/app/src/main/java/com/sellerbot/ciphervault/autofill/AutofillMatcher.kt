package com.sellerbot.ciphervault.autofill

import com.sellerbot.ciphervault.model.EntryType
import com.sellerbot.ciphervault.model.VaultEntry

/**
 * What the screen being filled looks like, reduced to the facts that decide
 * which credentials to offer.
 *
 * [webDomain] comes from browser form nodes and is authoritative.
 * [packageNames] is the fallback for native apps, where the only clue is the
 * application id. [focusedUsername] is whatever the user has already typed,
 * which is the strongest signal once a domain match has been ruled out.
 */
data class FillTarget(
    val webDomain: String? = null,
    val packageNames: Set<String> = emptySet(),
    val focusedUsername: String? = null,
)

/**
 * Chooses which stored credentials a fill request should offer, and in what
 * order.
 *
 * Pure by design: it takes [VaultEntry] values and returns them, with no
 * Android types anywhere, so every rule below is covered by JVM unit tests
 * rather than by manual tapping on a device.
 */
object AutofillMatcher {

    /**
     * Cap on what is returned. The system warns that a `FillResponse` travels
     * over Binder and a large one can exceed the transaction limit, so the
     * worst case is bounded here instead of at the call site.
     */
    const val MAX_RESULTS = 20

    /** Credential is for the site currently on screen. */
    private const val RANK_DOMAIN = 0
    /** Credential is for the app currently on screen, matched by package id. */
    private const val RANK_PACKAGE = 1
    /** No signal either way - offer it, but last. */
    private const val RANK_UNKNOWN = 2
    /** There was a signal and this credential did not satisfy it. */
    private const val RANK_NO_MATCH = 3

    private data class Scored(
        val entry: VaultEntry,
        val domainRank: Int,
        val usernameRank: Int,
        val favoriteRank: Int,
        val lastUsedRank: Long,
        val titleKey: String,
    )

    /**
     * Fillable logins, best match first.
     *
     * Entries with neither a username nor a password are dropped: they cannot
     * fill anything and would only pad the picker. Everything else survives so
     * a user who saved a credential against the wrong URL can still pick it
     * manually - ranking, not exclusion, is what keeps the right one on top.
     */
    fun rank(entries: List<VaultEntry>, target: FillTarget): List<VaultEntry> {
        val focused = target.focusedUsername?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        val packageHosts = target.packageNames
            .mapNotNull { Domains.hostFromPackageName(it) }
            .distinct()

        return entries
            .filter { it.type == EntryType.LOGIN }
            .filter { !it.password.isNullOrBlank() || !it.username.isNullOrBlank() }
            .map { entry ->
                Scored(
                    entry = entry,
                    domainRank = domainRank(entry, target.webDomain, packageHosts),
                    usernameRank = usernameRank(entry, focused),
                    favoriteRank = if (entry.favorite) 0 else 1,
                    // Descending: a never-used entry (0) sorts last without
                    // needing a null branch in the comparator.
                    lastUsedRank = -(entry.lastUsedAt ?: 0L),
                    titleKey = entry.title.trim().lowercase(),
                )
            }
            .sortedWith(
                compareBy(
                    { it.domainRank },
                    { it.usernameRank },
                    { it.favoriteRank },
                    { it.lastUsedRank },
                    { it.titleKey },
                    // Final tie-break so the picker does not reshuffle between
                    // two otherwise identical requests.
                    { it.entry.id },
                ),
            )
            .take(MAX_RESULTS)
            .map { it.entry }
    }

    private fun domainRank(entry: VaultEntry, webDomain: String?, packageHosts: List<String>): Int = when {
        !webDomain.isNullOrBlank() ->
            if (Domains.matches(entry.url, webDomain)) RANK_DOMAIN else RANK_NO_MATCH

        packageHosts.isNotEmpty() ->
            if (packageHosts.any { Domains.matches(entry.url, it) }) RANK_PACKAGE else RANK_UNKNOWN

        else -> RANK_UNKNOWN
    }

    private fun usernameRank(entry: VaultEntry, focused: String?): Int {
        if (focused == null) return 1
        val stored = entry.username?.trim()?.lowercase() ?: return 1
        return if (stored == focused) 0 else 1
    }
}
