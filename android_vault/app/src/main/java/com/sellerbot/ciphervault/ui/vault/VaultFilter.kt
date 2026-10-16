package com.sellerbot.ciphervault.ui.vault

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.StickyNote2
import androidx.compose.material.icons.automirrored.filled.ViewList
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Person
import androidx.compose.ui.graphics.vector.ImageVector
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.model.EntryType
import com.sellerbot.ciphervault.model.VaultEntry

/**
 * Drawer sections over the vault.
 *
 * These are *views*, not folders: an entry appears wherever its type and
 * favourite flag put it, and nothing is moved or rewritten by browsing one.
 * The distinction matters because a user who filters to Cards and deletes
 * "everything" must not be surprised that their logins survived.
 */
enum class VaultFilter(
    @StringRes val titleRes: Int,
    val icon: ImageVector,
) {
    ALL(R.string.nav_all, Icons.AutoMirrored.Filled.ViewList) {
        override fun matches(entry: VaultEntry): Boolean = true
    },

    LOGINS(R.string.nav_logins, Icons.Filled.LockOpen) {
        override fun matches(entry: VaultEntry): Boolean = entry.type == EntryType.LOGIN
    },

    FAVORITES(R.string.nav_favorites, Icons.Filled.Favorite) {
        override fun matches(entry: VaultEntry): Boolean = entry.favorite
    },

    /** Entries carrying a 2FA seed. Mirrored by the Authenticator section. */
    TWO_FACTOR(R.string.nav_2fa, Icons.Filled.Key) {
        override fun matches(entry: VaultEntry): Boolean = entry.hasTotp()
    },

    NOTES(R.string.nav_notes, Icons.AutoMirrored.Filled.StickyNote2) {
        override fun matches(entry: VaultEntry): Boolean = entry.type == EntryType.NOTE
    },

    CARDS(R.string.nav_cards, Icons.Filled.CreditCard) {
        override fun matches(entry: VaultEntry): Boolean = entry.type == EntryType.CARD
    },

    IDENTITY(R.string.nav_identity, Icons.Filled.Person) {
        override fun matches(entry: VaultEntry): Boolean = entry.type == EntryType.IDENTITY
    },
    ;

    abstract fun matches(entry: VaultEntry): Boolean

    /**
     * Named `select`, not `apply`.
     *
     * `apply` is also `kotlin.Standard.apply`, the scope function, and
     * `filter.apply(entries)` resolves to that one — returning the filter
     * itself instead of a list, with a cascade of type errors three files
     * away from the real mistake.
     */
    fun select(entries: List<VaultEntry>): List<VaultEntry> =
        entries.filter { !it.isTombstone() && (this == ALL || matches(it)) }
}

/** Shared so the 2FA badge and the Authenticator section agree on what counts. */
fun List<VaultEntry>.withTotp(): List<VaultEntry> =
    filter { !it.isTombstone() && it.hasTotp() }
