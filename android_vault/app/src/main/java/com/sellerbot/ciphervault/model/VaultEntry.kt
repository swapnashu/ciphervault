package com.sellerbot.ciphervault.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import java.util.UUID

/**
 * The plaintext vault schema.
 *
 * This is the *only* structure the server never sees: [Vault.serialize] output
 * is fed straight to [com.sellerbot.ciphervault.crypto.VaultCipher.encrypt] and
 * the resulting bytes are what gets uploaded.
 *
 * Every field has a default so that JSON written by an older app still
 * deserialises after an upgrade. There is no schema-migration machinery here
 * yet — if a field ever needs to change *meaning* rather than just be added,
 * that requires bumping [Vault.VERSION] and a real migration, because a
 * password manager cannot silently reinterpret stored bytes.
 */
@Serializable
data class Vault(
    val version: Int = VERSION,
    val entries: List<VaultEntry> = emptyList(),
    val folders: List<String> = emptyList(),
    /** Server revision this snapshot was read at; never encrypted for sync. */
    val revision: Int = 0,
) {
    fun serialize(): ByteArray = JSON.encodeToString(serializer(), this).toByteArray(Charsets.UTF_8)

    /** All entries that are not tombstones (i.e. visible to the user). */
    val liveEntries: List<VaultEntry>
        get() = entries.filter { !it.isTombstone() }

    fun entryById(id: String): VaultEntry? = liveEntries.firstOrNull { it.id == id }

    fun withEntry(entry: VaultEntry): Vault {
        val exists = liveEntries.any { it.id == entry.id }
        return copy(
            entries = if (exists) entries.map { if (it.id == entry.id) entry else it }
            else entries + entry,
            revision = 0, // any local edit invalidates the sync revision
        )
    }

    fun withoutEntry(id: String): Vault {
        val entry = liveEntries.firstOrNull { it.id == id }
            ?: return this
        return copy(
            entries = entries.map { if (it.id == id) it.delete() else it },
            revision = 0
        )
    }

    /**
     * Entry-level union of this snapshot with one just pulled from the server.
     *
     * Used to recover from a sync conflict: another device wrote between our
     * read and our write. Adopting the server snapshot wholesale discards the
     * edit the user just made; keeping ours alone discards theirs. So each
     * entry is taken from whichever side touched it later, and anything only
     * one side has is kept.
     *
     * Tombstone mechanism: entries marked as deleted (`deletedAt != null`) are
     * kept as tombstones and win over live entries in a merge, preventing
     * resurrection of deleted entries. Clock skew is mitigated by preferring
     * the entry from the vault with the higher `revision` (server-authoritative
     * ordering), falling back to `updatedAt` only when revisions are equal.
     */
    fun mergeWith(remote: Vault): Vault {
        val merged = LinkedHashMap<String, VaultEntry>(remote.entries.size + entries.size)

        // First pass: add all remote entries (server's view is authoritative for ordering)
        for (entry in remote.entries) merged[entry.id] = entry

        // Second pass: merge local entries
        for (entry in entries) {
            val theirs = merged[entry.id]
            val shouldKeepLocal = when {
                theirs == null -> true // We have an entry they don't
                entry.deletedAt != null && theirs.deletedAt == null -> true // Our tombstone wins over their live entry
                theirs.deletedAt != null && entry.deletedAt == null -> false // Their tombstone wins over our live entry
                entry.deletedAt != null && theirs.deletedAt != null -> entry.deletedAt!! >= theirs.deletedAt!! // Both tombstones: later deletion wins
                entry.revision != theirs.revision -> entry.revision > theirs.revision // Higher revision wins (server-authoritative)
                else -> entry.updatedAt >= theirs.updatedAt // Fallback to wall-clock time
            }
            if (shouldKeepLocal) merged[entry.id] = entry
        }

        return Vault(
            version = VERSION,
            entries = merged.values.toList(),
            folders = (folders + remote.folders).distinct(),
            revision = 0, // the merged snapshot has to be pushed again
        )
    }

    fun search(query: String): List<VaultEntry> {
        // Tombstones are kept in `entries` so a delete can be merged with
        // another device, but they are not things the user still has — they
        // must never surface in a search or a list.
        if (query.isBlank()) return liveEntries
        val needle = query.trim()
        return liveEntries.filter { entry ->
            entry.title.contains(needle, ignoreCase = true) ||
                entry.username?.contains(needle, ignoreCase = true) == true ||
                entry.url?.contains(needle, ignoreCase = true) == true ||
                entry.folder?.contains(needle, ignoreCase = true) == true ||
                entry.notes?.contains(needle, ignoreCase = true) == true
        }
    }

    /** Entries whose password has not been changed in [olderThanDays]. */
    fun stalePasswords(olderThanDays: Long = 365, now: Long = System.currentTimeMillis()): List<VaultEntry> =
        entries.filter { entry ->
            val stamped = entry.passwordUpdatedAt ?: entry.updatedAt
            now - stamped > olderThanDays * MILLIS_PER_DAY
        }

    companion object {
        const val VERSION = 1
        const val MILLIS_PER_DAY = 86_400_000L

        val JSON: Json = Json {
            // Text is written as UTF-8 rather than \uXXXX escapes, so any
            // script or punctuation a user pastes in round-trips exactly.
            ignoreUnknownKeys = true   // forward compatibility
            encodeDefaults = true      // never write an implicit value the reader might default differently
            prettyPrint = false        // smaller blob, marginally less to encrypt
        }

        val EMPTY = Vault()

        /**
         * Parse a decrypted vault. Returns [EMPTY] for an empty payload rather
         * than throwing, because a brand-new account legitimately has no blob.
         */
        fun deserialize(bytes: ByteArray): Vault {
            if (bytes.isEmpty()) return EMPTY
            return try {
                JSON.decodeFromString(serializer(), String(bytes, Charsets.UTF_8))
            } catch (e: SerializationException) {
                // Corrupt or tampered. GCM already authenticated the bytes, so
                // this means a bug or a version the app does not understand —
                // never guess at partial contents.
                throw IllegalStateException("Vault contents could not be parsed", e)
            }
        }
    }
}

enum class EntryType {
    LOGIN, NOTE, CARD, IDENTITY,
    /** A 2FA seed with nothing else attached — behaves like Google Authenticator. */
    TOTP,
}

@Serializable
data class CustomField(
    val label: String,
    val value: String,
    val hidden: Boolean = false,
)

/**
 * One credential. Optional fields stay null rather than empty-string so that
 * "absent" and "present but blank" remain distinguishable, which matters when
 * deciding whether a field should be filled into another app.
 */
@Serializable
data class VaultEntry(
    val id: String = UUID.randomUUID().toString(),
    val type: EntryType = EntryType.LOGIN,
    val title: String,
    val username: String? = null,
    val password: String? = null,
    /** Base32 secret for the TOTP generator. */
    val totpSecret: String? = null,
    /**
     * TOTP parameters, optional because most enrolments are the RFC defaults.
     *
     * Added after the initial schema shipped, which is safe here for exactly
     * the reason the class comment gives: these are *additions* with
     * defaults, not a change of meaning. An older blob decodes to the
     * defaults and keeps working; a newer blob read by an older app has the
     * keys ignored rather than misread. An authenticator that silently
     * generates the wrong code is worse than one that shows none, so the
     * parameters a QR code carries have to survive the round-trip.
     */
    val totpAlgorithm: String? = null,
    val totpDigits: Int? = null,
    val totpPeriodSeconds: Int? = null,
    val url: String? = null,
    val notes: String? = null,
    val folder: String? = null,
    val favorite: Boolean = false,
    val customFields: List<CustomField> = emptyList(),
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    /** Per-entry logical revision, incremented on each change. Used for merge conflict resolution. */
    val revision: Int = 0,
    /** Tombstone timestamp: when non-null, the entry is considered deleted. */
    val deletedAt: Long? = null,
    /** Set when the password changes, drives the stale-password audit. */
    val passwordUpdatedAt: Long? = null,
    /** Last time a TOTP code for this entry was copied, for recent-ordering. */
    val lastUsedAt: Long? = null,
) {
    /** True when there is a 2FA seed to show on the detail screen. */
    fun hasTotp(): Boolean = !totpSecret.isNullOrBlank()

    /** True if this entry uses a deprecated algorithm (SHA-1). */
    fun isDeprecatedAlgorithm(): Boolean = totpAlgorithm?.let {
        com.sellerbot.ciphervault.crypto.Totp.Algorithm.fromUri(it) == com.sellerbot.ciphervault.crypto.Totp.Algorithm.SHA1
    } ?: false

    /** True if this entry is a tombstone (deleted but kept for merge). */
    fun isTombstone(): Boolean = deletedAt != null

    fun markUsed(now: Long = System.currentTimeMillis()): VaultEntry =
        copy(lastUsedAt = now, revision = revision)

    fun withPassword(newPassword: String, now: Long = System.currentTimeMillis()): VaultEntry =
        copy(password = newPassword, passwordUpdatedAt = now, updatedAt = now, revision = revision + 1)

    /** Mark this entry as deleted (tombstone) for merge conflict resolution. */
    fun delete(now: Long = System.currentTimeMillis()): VaultEntry =
        copy(deletedAt = now, updatedAt = now, revision = revision + 1)

    /** Everything a user would consider a secret, for clipboard clearing. */
    fun secrets(): List<String> = buildList {
        password?.let { add(it) }
        totpSecret?.let { add(it) }
        customFields.filter { it.hidden }.forEach { add(it.value) }
    }
}
