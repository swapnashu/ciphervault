package com.sellerbot.ciphervault.sync

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire DTOs for the `/vault/api/` routes.
 *
 * Caution: Kotlin block comments nest, so a slash-asterisk pair written
 * anywhere inside a KDoc opens a comment that never closes and silently
 * swallows the remainder of the file.
 *
 * Field-by-field mirror of `sellerbot/vault/api.py`, which is pinned by
 * `tests/test_vault_api.py`. If one side changes, that test file is what
 * breaks — so change the Python tests first, then this file.
 */

// ---- Health ----------------------------------------------------------------

@Serializable
data class HealthResponse(
    val status: String,
    val service: String,
    @SerialName("kdf_default_iterations") val kdfDefaultIterations: Int,
)

// ---- Prelogin --------------------------------------------------------------

@Serializable
data class PreloginRequest(
    val email: String,
)

/**
 * Returned for *any* address: real accounts get their stored salt, unknown
 * ones get a deterministic dummy. The client cannot tell the difference, which
 * is the point.
 */
@Serializable
data class PreloginResponse(
    @SerialName("kdf_salt") val kdfSalt: String,
    val kdf: KdfParams,
)

@Serializable
data class KdfParams(
    val algo: String,
    val iterations: Int,
    @SerialName("memory_kib") val memoryKib: Int? = null,
    val parallelism: Int? = null,
)

// ---- Register --------------------------------------------------------------

@Serializable
data class RegisterRequest(
    val email: String,
    @SerialName("kdf_salt") val kdfSalt: String,
    val kdf: KdfParams,
    @SerialName("auth_key") val authKey: String,
)

@Serializable
data class RegisterResponse(
    @SerialName("user_id") val userId: String,
)

// ---- Login -----------------------------------------------------------------

@Serializable
data class LoginRequest(
    val email: String,
    @SerialName("auth_key") val authKey: String,
    val device: String? = null,
)

@Serializable
data class LoginResponse(
    @SerialName("session_token") val sessionToken: String,
    @SerialName("user_id") val userId: String,
    @SerialName("vault_revision") val vaultRevision: Int,
    @SerialName("expires_at") val expiresAt: String,
)

// ---- Blob sync -------------------------------------------------------------

@Serializable
data class BlobResponse(
    val ciphertext: String? = null,
    val revision: Int,
    @SerialName("updated_at") val updatedAt: String? = null,
)

@Serializable
data class PutBlobRequest(
    val ciphertext: String,
    @SerialName("base_revision") val baseRevision: Int,
)

@Serializable
data class PutBlobResponse(
    val revision: Int? = null,
    val error: String? = null,
    val message: String? = null,
    val ciphertext: String? = null,
)

// ---- Sessions --------------------------------------------------------------

@Serializable
data class SessionInfo(
    val device: String? = null,
    @SerialName("created_at") val createdAt: String,
    @SerialName("last_seen") val lastSeen: String,
    @SerialName("expires_at") val expiresAt: String,
    val current: Boolean = false,
)

@Serializable
data class SessionsResponse(
    val sessions: List<SessionInfo>,
)

@Serializable
data class RevokeOthersResponse(
    val revoked: Int,
)

// ---- KDF migration / password change ---------------------------------------

/**
 * Body for `/migrate-kdf` and `/change-password` — identical on the wire.
 *
 * `authKey` proves the *current* password (server checks it against the
 * verifier stored under the current params), `newAuthKey` is the replacement
 * verifier under `kdf`, and `ciphertext` is the vault re-encrypted under the
 * new KDF. The server commits verifier and blob in one transaction: the
 * encryption key is an HKDF sibling of the auth key, so one without the
 * other would lock every device out.
 */
@Serializable
data class KdfChangeRequest(
    @SerialName("auth_key") val authKey: String,
    @SerialName("new_auth_key") val newAuthKey: String,
    @SerialName("kdf_salt") val kdfSalt: String,
    val kdf: KdfParams,
    val ciphertext: String,
    @SerialName("base_revision") val baseRevision: Int,
)

@Serializable
data class MigrateKdfResponse(
    val changed: Boolean? = null,
    val kdf: KdfParams? = null,
    val revision: Int? = null,
    val error: String? = null,
    val message: String? = null,
    val ciphertext: String? = null,
)

@Serializable
data class ChangePasswordResponse(
    val changed: Boolean? = null,
    val revision: Int? = null,
    @SerialName("revoked_sessions") val revokedSessions: Int? = null,
    val error: String? = null,
    val message: String? = null,
    val ciphertext: String? = null,
)

// ---- Audit log --------------------------------------------------------------

@Serializable
data class AuditEvent(
    val event: String,
    val detail: String? = null,
    val ip: String? = null,
    val at: String,
)

@Serializable
data class AuditResponse(
    val total: Int,
    val events: List<AuditEvent>,
)

// ---- Errors ----------------------------------------------------------------

/**
 * The server's uniform error body. Every non-2xx from the vault API carries
 * this shape, which is what lets the client distinguish "wrong password"
 * from "rate limited" from "sync conflict" without parsing HTML.
 */
@Serializable
data class ApiErrorBody(
    val error: String,
    val message: String,
) {
    companion object {
        const val RATE_LIMITED = "rate_limited"
        const val INVALID_CREDENTIALS = "invalid_credentials"
        const val EMAIL_TAKEN = "email_taken"
        const val CONFLICT = "conflict"
        const val UNAUTHORIZED = "unauthorized"
        const val BLOB_TOO_LARGE = "blob_too_large"
    }
}
