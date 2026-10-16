package com.sellerbot.ciphervault.repo

import android.os.Build
import androidx.annotation.VisibleForTesting
import com.sellerbot.ciphervault.crypto.Hkdf
import com.sellerbot.ciphervault.crypto.Kdf
import com.sellerbot.ciphervault.crypto.VaultCipher
import com.sellerbot.ciphervault.model.Vault
import com.sellerbot.ciphervault.sync.AuditResponse
import com.sellerbot.ciphervault.sync.KdfChangeRequest
import com.sellerbot.ciphervault.sync.KdfParams
import com.sellerbot.ciphervault.sync.LoginRequest
import com.sellerbot.ciphervault.sync.PreloginRequest
import com.sellerbot.ciphervault.sync.PutBlobRequest
import com.sellerbot.ciphervault.sync.RegisterRequest
import com.sellerbot.ciphervault.sync.SessionInfo
import com.sellerbot.ciphervault.sync.VaultApi
import com.sellerbot.ciphervault.sync.VaultApiException
import com.sellerbot.ciphervault.sync.unwrapOrThrow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.Base64

/**
 * Orchestrates key derivation, encryption and sync.
 *
 * ── The AAD convention ────────────────────────────────────────────────────
 * The blob is bound to ``(userId, revision)`` via AES-GCM additional data so
 * ciphertext lifted from one account cannot be replayed into another, and so
 * a server silently serving an old blob fails to decrypt:
 *
 *     read  blob that lives at revision N  →  AAD = context(userId, N)
 *     write blob that will live at rev N+1 →  AAD = context(userId, N+1)
 *
 * In other words: **the AAD revision is always the revision of the blob being
 * read or written.** The writer predicts its own destination revision as
 * `base_revision + 1`, which is exactly what the server assigns on success.
 * If the write is rejected with a conflict the prediction was wrong anyway,
 * the client re-pulls and retries, and nothing is lost.
 *
 * ── What lives where ──────────────────────────────────────────────────────
 *   master password  → never stored, never transmitted
 *   masterKey        → derived on demand, zeroed on [lock]
 *   authKey          → transmitted once per login; server stores only sha256 of it
 *   encKey           → never leaves this process
 *   ciphertext       → the only thing the server keeps
 */
class VaultRepository(
    private val api: VaultApi,
    private val credentials: CredentialStore,
) {

    /**
     * The encryption sub-key, held only while unlocked and zeroed by [lock].
     *
     * The `auth` sub-key is deliberately *not* retained: it is used exactly
     * once per login and then discarded, so a process dump cannot recover it.
     */
    private var encKey: ByteArray? = null

    /**
     * Set when the server has rejected our bearer token (401 on an
     * authenticated call).
     *
     * Sessions expire server-side (7 days) and `unlock()` verifies the
     * password *locally*, so a returning device can open a vault whose
     * token is long dead — every sync then fails and there was no path
     * back to a working session short of clearing app data. The flag turns
     * that into a re-login on the next master-password unlock.
     *
     * Biometric unlock cannot use it (there is no password to re-derive
     * from), which is why the UI tells the user to unlock with the
     * master password when this fires.
     */
    @Volatile
    private var sessionStale: Boolean = false

    /** True when the stored session token needs replacing before syncing. */
    val sessionNeedsRelogin: Boolean get() = sessionStale

    private fun noteAuthFailure(throwable: Throwable) {
        if (throwable is VaultApiException && throwable.isAuthFailure) {
            sessionStale = true
        }
    }

    val isUnlocked: Boolean get() = encKey != null

    /**
     * The decrypted vault while unlocked, null as soon as [lock] runs.
     *
     * The UI keeps this in its own state, but the autofill service runs in a
     * different component of the same process and has no way to reach the
     * activity's ViewModel. Publishing it here rather than in a free-floating
     * singleton is deliberate: [lock] is the single place that drops key
     * material, so the `onTrimMemory` path — which locks without ever passing
     * through the UI — drops the plaintext with it.
     *
     * Guarded by [encKey] on read: even if a caller forgets to clear it, a
     * locked vault returns nothing.
     */
    @Volatile
    private var publishedVault: Vault? = null

    /** Decrypted vault for out-of-UI readers, or null when locked. */
    val openVault: Vault?
        get() = if (encKey != null) publishedVault else null

    /** Publish the snapshot the UI is currently showing. No-op while locked. */
    fun publishVault(vault: Vault) {
        publishedVault = if (encKey != null) vault else null
    }

    /** Drop the snapshot without touching the key (UI leaving the unlocked state). */
    fun clearPublishedVault() {
        publishedVault = null
    }

    /**
     * True once this device has an account (email + KDF salt stored).
     * Drives the Setup-vs-Locked split in the UI so a fresh install is never
     * offered "unlock" and a registered device is never offered "sign up".
     */
    val hasLocalAccount: Boolean
        get() = !credentials.userEmail.isNullOrBlank() &&
            !credentials.kdfSaltBase64.isNullOrBlank()

    /** Account hint for the lock screen; null on a fresh install. */
    val accountEmail: String? get() = credentials.userEmail

    /**
     * True when the user has turned biometric unlock on for this device.
     * Presence of the wrapped blob is what matters — the Keystore alias alone
     * is created during enrolment, but the blob is what makes unlock possible.
     */
    val hasWrappedBiometricKey: Boolean
        get() = !credentials.wrappedVaultKeyBase64.isNullOrBlank()

    /**
     * Install an already-unwrapped encryption key. This is the biometric
     * unlock path: [com.sellerbot.ciphervault.security.KeystoreManager]
     * decrypts the wrapped key inside the `BiometricPrompt` callback (which is
     * the only moment the Keystore key is usable), and hands us the result.
     *
     * The caller does the unwrap so the repository stays independent of the
     * Android Keystore, which has no JVM-testable implementation.
     */
    fun acceptEncryptionKey(key: ByteArray) {
        require(key.size == VaultCipher.KEY_BYTES) {
            "Encryption key must be ${VaultCipher.KEY_BYTES} bytes, was ${key.size}"
        }
        encKey?.fill(0)
        encKey = key
    }

    /**
     * A copy of the encryption key, used to enrol it into device-local
     * biometric storage while the vault is open. Null when locked.
     *
     * The caller **must** `fill(0)` the returned array once enrolment
     * finishes (on every outcome, including cancel): it is the same material
     * that decrypts the vault, and a prompt can stay open indefinitely.
     */
    fun copyEncryptionKey(): ByteArray? = encKey?.copyOf()

    // ---- Registration -----------------------------------------------------

    /**
     * Create a brand-new account.
     *
     * Flow: register the KDF parameters and auth verifier, log in to obtain a
     * session token (the register endpoint deliberately issues none, so a
     * registration cannot be turned into an authenticated session by a
     * middleman), then seed the server with an empty vault blob.
     *
     * @return the user id
     * @throws VaultApiException on 409 (email taken), 429 (rate limited), etc.
     */
    suspend fun register(email: String, password: CharArray): Result<String> = register(email, password, Kdf.Params())

    /**
     * Test-only overload allowing injection of fast KDF parameters.
     * Production code must use the no-arg version which uses secure defaults.
     */
    @VisibleForTesting
    suspend fun register(email: String, password: CharArray, params: Kdf.Params): Result<String> =
        withContext(Dispatchers.IO) {
            runCatching {
                val normalised = email.trim().lowercase()
                val salt = Kdf.generateSalt()
                val (derivedAuth, derivedEnc) = derive(password, salt, params)

                val userId = try {
                    val created = api.register(
                        RegisterRequest(
                            email = normalised,
                            kdfSalt = salt.encode(),
                            kdf = KdfParams(
                                algo = params.algorithm.name,
                                iterations = params.iterations,
                                memoryKib = params.memoryKiB,
                                parallelism = params.parallelism,
                            ),
                            authKey = derivedAuth.encode(),
                        )
                    ).unwrapOrThrow()

                    val session = api.login(
                        LoginRequest(
                            email = normalised,
                            authKey = derivedAuth.encode(),
                            device = deviceName(),
                        )
                    ).unwrapOrThrow()

                    credentials.apply {
                        userEmail = normalised
                        this.userId = created.userId
                        sessionToken = session.sessionToken
                        kdfSaltBase64 = salt.encode()
                        kdfIterations = params.iterations
                        kdfAlgorithm = params.algorithm.name
                        kdfMemoryKib = params.memoryKiB
                        kdfParallelism = params.parallelism
                        localRevision = session.vaultRevision
                        authKeyVerifierHex = hashHex(derivedAuth)
                    }
                    sessionStale = false
                    created.userId
                } catch (t: Throwable) {
                    derivedEnc.fill(0)
                    throw t
                } finally {
                    derivedAuth.fill(0)
                }

                encKey = derivedEnc

                // Seed an empty vault so the first real edit has a revision to
                // conflict-check against. If the seed fails, the account exists
                // but the vault isn't initialized — treat it as a registration
                // failure so the user doesn't get a half-created account.
                push(Vault.EMPTY).getOrThrow()

                userId
            }
        }

    private fun deviceName(): String =
        "${Build.MANUFACTURER ?: "Unknown"} ${Build.MODEL ?: "device"}"

    // ---- Login ------------------------------------------------------------

    suspend fun login(email: String, password: CharArray, device: String?): Result<Int> =
        withContext(Dispatchers.IO) {
            runCatching {
                val normalised = email.trim().lowercase()

                val prelogin = api.prelogin(PreloginRequest(normalised)).unwrapOrThrow()
                val salt = prelogin.kdfSalt.decode()
                val params = Kdf.Params(
                    algorithm = Kdf.Params.Algorithm.fromStored(prelogin.kdf.algo),
                    iterations = prelogin.kdf.iterations,
                    memoryKiB = prelogin.kdf.memoryKib ?: Kdf.DEFAULT_ARGON2_MEMORY_KIB,
                    parallelism = prelogin.kdf.parallelism ?: Kdf.DEFAULT_ARGON2_LANES,
                )

                val (derivedAuth, derivedEnc) = derive(password, salt, params)
                try {
                    val session = api.login(
                        LoginRequest(
                            email = normalised,
                            authKey = derivedAuth.encode(),
                            device = device,
                        )
                    ).unwrapOrThrow()

                    credentials.apply {
                        userEmail = normalised
                        userId = session.userId
                        sessionToken = session.sessionToken
                        kdfSaltBase64 = prelogin.kdfSalt
                        kdfIterations = params.iterations
                        kdfAlgorithm = prelogin.kdf.algo
                        kdfMemoryKib = params.memoryKiB
                        kdfParallelism = params.parallelism
                        localRevision = session.vaultRevision
                        authKeyVerifierHex = hashHex(derivedAuth)
                        paramsStale = false
                    }
                    sessionStale = false
                    encKey = derivedEnc
                    session.vaultRevision
                } catch (t: Throwable) {
                    // A rejected login is the common case here (wrong password),
                    // and the key derived from it must not outlive the attempt.
                    derivedEnc.fill(0)
                    throw t
                } finally {
                    derivedAuth.fill(0)
                }
            }
        }

    /**
     * Re-derive keys from the locally stored salt, for a returning device.
     *
     * The password is **verified**, not trusted. Deriving a key and assuming
     * it is the right one fails open in two ways, and both were reachable:
     *
     *   1. An account whose vault is still empty has nothing to decrypt, so
     *      `pull()` returns `Empty` without ever touching the key and any
     *      password produced a clean blank vault with no error at all.
     *   2. `refreshAfterUnlock()` sets the UI to `Unlocked` *before* the pull
     *      runs, so when the vault was populated and the GCM tag failed the
     *      user was still left sitting in the unlocked shell behind a
     *      "Something went wrong" banner.
     *
     * The check is the same `sha256(authKey)` verifier the server keeps, so
     * unlocking works offline and costs no server round trip. `authKey` and
     * `encKey` are HKDF siblings of one master key, so proving the first
     * proves the second.
     *
     * Installs that predate the stored verifier have nothing to compare
     * against; those authenticate against the server once and pick the
     * verifier up on the way through.
     */
    suspend fun unlock(password: CharArray): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                // Another device moved the key material while this one was
                // away: the local salt/verifier cannot read its blob or pass
                // its checks. Adopt the server's parameters; the login inside
                // proves the password before anything is stored.
                if (credentials.paramsStale) {
                    relinkFromServer(password)
                    maybeMigrate(password)
                    return@runCatching
                }

                val saltB64 = credentials.kdfSaltBase64
                    ?: throw IllegalStateException("No account on this device")
                val salt = saltB64.decode()
                val params = localParams()

                val (derivedAuth, derivedEnc) = derive(password, salt, params)
                try {
                    if (verifyOrUpgrade(password, derivedAuth)) {
                        // The session may have expired while the device was away.
                        // Swap it for a live one so the first sync does not 401 —
                        // only reachable *after* the local verifier passed, so this
                        // can never turn into an online password oracle.
                        if (sessionStale) reauthenticate(derivedAuth)

                        encKey?.fill(0)
                        encKey = derivedEnc
                    } else {
                        // Relinked to the server's parameters, which installed
                        // their own key; the locally derived one must not live on.
                        derivedEnc.fill(0)
                    }
                    maybeMigrate(password)
                } catch (t: Throwable) {
                    derivedEnc.fill(0)
                    throw t
                } finally {
                    derivedAuth.fill(0)
                }
            }
        }

    /**
     * Replace a session token the server has rejected.
     *
     * Unlike the rest of [unlock] this needs the network. Failing here is
     * correct: without a live token nothing can be synced, so the caller
     * surfaces the network error rather than opening a vault that can only
     * ever lose the user's next edit.
     */
    private suspend fun reauthenticate(derivedAuth: ByteArray) {
        val email = credentials.userEmail
            ?: throw IllegalStateException("No account on this device")
        val session = api.login(
            LoginRequest(
                email = email,
                authKey = derivedAuth.encode(),
                device = deviceName(),
            ),
        ).unwrapOrThrow()
        credentials.sessionToken = session.sessionToken
        credentials.localRevision = session.vaultRevision
        sessionStale = false
    }

    /**
     * Check [derivedAuth] against the stored verifier, or against the server
     * when this install predates local verifiers.
     *
     * A mismatch is not immediately fatal: this device's verifier can go stale
     * behind another device's password change or KDF migration, so the server
     * is asked when reachable. Offline there is nothing better than the local
     * verdict, and that is what surfaces.
     *
     * @return true when the caller should continue with the locally derived
     *         keys; false when a stale copy was relinked to the server (which
     *         then installed its own key).
     * @throws IllegalArgumentException with a user-facing message when the
     *         password is wrong and the server cannot be reached.
     * @throws VaultApiException when the server rejects the password — its
     *         message is phrased for users and carries the same text.
     */
    private suspend fun verifyOrUpgrade(password: CharArray, derivedAuth: ByteArray): Boolean {
        val stored = credentials.authKeyVerifierHex
        if (stored != null) {
            val ok = MessageDigest.isEqual(
                hashHex(derivedAuth).toByteArray(StandardCharsets.US_ASCII),
                stored.toByteArray(StandardCharsets.US_ASCII),
            )
            if (ok) return true

            try {
                relinkFromServer(password)
                return false
            } catch (e: VaultApiException) {
                throw e
            } catch (_: IOException) {
                throw IllegalArgumentException("Email or password is incorrect")
            }
        }

        // Legacy path: no local verifier yet. Prove the password to the
        // server, which also hands back a fresh session token, and record the
        // verifier so every later unlock is offline.
        val email = credentials.userEmail
            ?: throw IllegalStateException("No account on this device")
        val session = api.login(
            LoginRequest(
                email = email,
                authKey = derivedAuth.encode(),
                device = deviceName(),
            ),
        ).unwrapOrThrow()
        credentials.sessionToken = session.sessionToken
        sessionStale = false
        credentials.localRevision = session.vaultRevision
        credentials.authKeyVerifierHex = hashHex(derivedAuth)
        return true
    }

    /**
     * Adopt the server's current KDF parameters and a fresh session.
     *
     * Used when this device's copy has diverged: a failed decrypt after
     * another device migrated the KDF or changed the password, or a local
     * verifier that disagrees with what was typed. The login proves the
     * password against the server's *current* verifier before anything is
     * stored, so nothing here is trusted blindly; offline this throws an
     * [IOException] and the caller decides what that means.
     */
    private suspend fun relinkFromServer(password: CharArray) {
        val email = credentials.userEmail
            ?: throw IllegalStateException("No account on this device")
        val prelogin = api.prelogin(PreloginRequest(email)).unwrapOrThrow()
        val salt = prelogin.kdfSalt.decode()
        val params = Kdf.Params(
            algorithm = Kdf.Params.Algorithm.fromStored(prelogin.kdf.algo),
            iterations = prelogin.kdf.iterations,
            memoryKiB = prelogin.kdf.memoryKib ?: Kdf.DEFAULT_ARGON2_MEMORY_KIB,
            parallelism = prelogin.kdf.parallelism ?: Kdf.DEFAULT_ARGON2_LANES,
        )

        val (derivedAuth, derivedEnc) = derive(password, salt, params)
        try {
            val session = api.login(
                LoginRequest(
                    email = email,
                    authKey = derivedAuth.encode(),
                    device = deviceName(),
                ),
            ).unwrapOrThrow()
            credentials.apply {
                userEmail = email
                userId = session.userId
                sessionToken = session.sessionToken
                kdfSaltBase64 = prelogin.kdfSalt
                kdfIterations = params.iterations
                kdfAlgorithm = prelogin.kdf.algo
                kdfMemoryKib = params.memoryKiB
                kdfParallelism = params.parallelism
                localRevision = session.vaultRevision
                authKeyVerifierHex = hashHex(derivedAuth)
                paramsStale = false
            }
            sessionStale = false
            encKey?.fill(0)
            encKey = derivedEnc
        } catch (t: Throwable) {
            derivedEnc.fill(0)
            throw t
        } finally {
            derivedAuth.fill(0)
        }
    }

    /**
     * Move this account onto the server's current KDF default — best effort.
     *
     * Fires only for the pre-Argon2 install case: this account still runs
     * PBKDF2 while the server advertises a memory-hard default
     * (`health.kdf_default_iterations` far below any PBKDF2 round count).
     * Every failure is swallowed: the attempt is retried on the next unlock,
     * and the server commits verifier and blob in one transaction, so there
     * is no half-migrated state to clean up. A 409 means another device won
     * the race — flagging [CredentialStore.paramsStale] makes the next unlock
     * adopt its parameters instead.
     *
     * Never throws: [unlock] calls it after the key is installed, and an
     * unexpected error here must not tear the freshly opened vault down.
     */
    private suspend fun maybeMigrate(password: CharArray) {
        runCatching {
            if (!credentials.hasSession()) return
            if (credentials.kdfAlgorithm != Kdf.Params.Algorithm.PBKDF2_SHA256.name) return

            val health = api.health().unwrapOrThrow()
            // A PBKDF2 round count is >= 100k. The server reporting anything
            // smaller means its current default is memory-hard (Argon2id
            // passes), which is exactly when a PBKDF2 account should upgrade.
            if (health.kdfDefaultIterations >= Kdf.MIN_PBKDF2_ITERATIONS) return

            val userId = credentials.userId ?: return
            val currentSalt = (credentials.kdfSaltBase64 ?: return).decode()
            // Iterations only: PBKDF2 accounts store the default memory and
            // lanes, and building from the stored values would be pointless
            // (they are ignored) — but could trip the floor checks if a very
            // old install recorded something odd.
            val currentParams = Kdf.Params(
                algorithm = Kdf.Params.Algorithm.PBKDF2_SHA256,
                iterations = credentials.kdfIterations,
            )

            val newSalt = Kdf.generateSalt()
            val newParams = Kdf.Params()
            val (newAuth, newEnc) = derive(password, newSalt, newParams)
            var adopted = false
            try {
                val (currentAuth, currentEnc) = derive(password, currentSalt, currentParams)
                try {
                    val response = api.getBlob().unwrapOrThrow()
                    val payload = response.ciphertext
                    val plain = if (payload.isNullOrBlank()) {
                        Vault.EMPTY.serialize()
                    } else {
                        val key = encKey ?: throw IllegalStateException("Vault is locked")
                        try {
                            VaultCipher.decrypt(
                                blob = payload.decode(),
                                key = key,
                                additionalData = VaultCipher.accountContext(userId, response.revision),
                            )
                        } catch (t: GeneralSecurityException) {
                            // The blob is already under someone else's key:
                            // this device's copy is the stale one.
                            credentials.paramsStale = true
                            throw t
                        }
                    }
                    val blob = try {
                        VaultCipher.encrypt(
                            plaintext = plain,
                            key = newEnc,
                            additionalData = VaultCipher.accountContext(userId, response.revision + 1),
                        )
                    } finally {
                        plain.fill(0)
                    }

                    val migrate = api.migrateKdf(
                        KdfChangeRequest(
                            authKey = currentAuth.encode(),
                            newAuthKey = newAuth.encode(),
                            kdfSalt = newSalt.encode(),
                            kdf = KdfParams(
                                algo = newParams.algorithm.name,
                                iterations = newParams.iterations,
                                memoryKib = newParams.memoryKiB,
                                parallelism = newParams.parallelism,
                            ),
                            ciphertext = blob.encode(),
                            baseRevision = response.revision,
                        ),
                    )
                    if (migrate.code() == 409) {
                        credentials.paramsStale = true
                        return
                    }
                    val body = migrate.unwrapOrThrow()
                    if (body.changed != true || body.revision == null) return

                    credentials.apply {
                        kdfSaltBase64 = newSalt.encode()
                        kdfAlgorithm = newParams.algorithm.name
                        kdfIterations = newParams.iterations
                        kdfMemoryKib = newParams.memoryKiB
                        kdfParallelism = newParams.parallelism
                        authKeyVerifierHex = hashHex(newAuth)
                        localRevision = body.revision
                        // The biometric blob wraps the *old* encryption key;
                        // keeping it would promise an unlock that cannot read
                        // the migrated vault.
                        wrappedVaultKeyBase64 = null
                    }
                    encKey?.fill(0)
                    encKey = newEnc
                    adopted = true
                } finally {
                    currentAuth.fill(0)
                    currentEnc.fill(0)
                }
            } finally {
                newAuth.fill(0)
                if (!adopted) newEnc.fill(0)
            }
        }.onFailure(::noteAuthFailure)
    }

    /**
     * Replace the master password: re-encrypt [vault] under a fresh salt and
     * the current default KDF, then have the server commit the new verifier
     * and blob in one transaction, revoking every other session.
     *
     * The current password is proved locally first (when a local verifier
     * exists) so the server never sees an attempt this device can reject;
     * the server then proves it again as part of the commit.
     *
     * @return the new server revision.
     * @throws VaultApiException on 409 (another device wrote first — the
     *         server rolled this change back whole), 401, 429, ...
     */
    suspend fun changeMasterPassword(
        current: CharArray,
        updated: CharArray,
        vault: Vault,
    ): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            requireValidKeys()
            val email = credentials.userEmail
                ?: throw IllegalStateException("No account on this device")
            val userId = credentials.userId
                ?: throw IllegalStateException("Not logged in")
            if (!credentials.hasSession()) {
                throw IllegalStateException(
                    "Your session has expired. Lock the vault, then unlock " +
                        "with your master password to sign in again.",
                )
            }

            val currentSalt = (credentials.kdfSaltBase64 ?: throw IllegalStateException("No account on this device")).decode()
            val currentParams = localParams()
            val (currentAuth, currentEnc) = derive(current, currentSalt, currentParams)
            try {
                val stored = credentials.authKeyVerifierHex
                if (stored != null && !credentials.paramsStale) {
                    val ok = MessageDigest.isEqual(
                        hashHex(currentAuth).toByteArray(StandardCharsets.US_ASCII),
                        stored.toByteArray(StandardCharsets.US_ASCII),
                    )
                    if (!ok) throw IllegalArgumentException("Email or password is incorrect")
                }

                val newSalt = Kdf.generateSalt()
                val newParams = Kdf.Params()
                val (newAuth, newEnc) = derive(updated, newSalt, newParams)
                var adopted = false
                try {
                    val baseRevision = credentials.localRevision
                    val plain = vault.serialize()
                    val blob = try {
                        VaultCipher.encrypt(
                            plaintext = plain,
                            key = newEnc,
                            additionalData = VaultCipher.accountContext(userId, baseRevision + 1),
                        )
                    } finally {
                        plain.fill(0)
                    }

                    val response = api.changePassword(
                        KdfChangeRequest(
                            authKey = currentAuth.encode(),
                            newAuthKey = newAuth.encode(),
                            kdfSalt = newSalt.encode(),
                            kdf = KdfParams(
                                algo = newParams.algorithm.name,
                                iterations = newParams.iterations,
                                memoryKib = newParams.memoryKiB,
                                parallelism = newParams.parallelism,
                            ),
                            ciphertext = blob.encode(),
                            baseRevision = baseRevision,
                        ),
                    )
                    if (response.code() == 409) {
                        // Another device wrote first; the server rolled our
                        // change back whole (verifier, blob and revocations
                        // together), so the local state still stands and the
                        // server's message is what the user needs to see.
                        throw VaultApiException.from(response)
                    }
                    val body = response.unwrapOrThrow()
                    val newRevision = body.revision
                        ?: throw VaultApiException(response.code(), "bad_response", "Missing revision")

                    credentials.apply {
                        kdfSaltBase64 = newSalt.encode()
                        kdfAlgorithm = newParams.algorithm.name
                        kdfIterations = newParams.iterations
                        kdfMemoryKib = newParams.memoryKiB
                        kdfParallelism = newParams.parallelism
                        authKeyVerifierHex = hashHex(newAuth)
                        localRevision = newRevision
                        wrappedVaultKeyBase64 = null
                        paramsStale = false
                    }
                    sessionStale = false
                    encKey?.fill(0)
                    encKey = newEnc
                    adopted = true
                    newRevision
                } finally {
                    newAuth.fill(0)
                    if (!adopted) newEnc.fill(0)
                }
            } finally {
                currentAuth.fill(0)
                currentEnc.fill(0)
            }
        }.onFailure(::noteAuthFailure)
    }

    /** The signed-in account's own security log, newest first. */
    suspend fun auditEvents(limit: Int = 50): Result<AuditResponse> =
        withContext(Dispatchers.IO) {
            runCatching { api.audit(limit).unwrapOrThrow() }
        }.onFailure(::noteAuthFailure)

    /** This account's active sessions, newest first. */
    suspend fun activeSessions(): Result<List<SessionInfo>> =
        withContext(Dispatchers.IO) {
            runCatching { api.sessions().unwrapOrThrow().sessions }
        }.onFailure(::noteAuthFailure)

    /** Sign out everywhere else. This device's session survives. */
    suspend fun revokeOtherSessions(): Result<Int> =
        withContext(Dispatchers.IO) {
            runCatching { api.revokeOtherSessions().unwrapOrThrow().revoked }
        }.onFailure(::noteAuthFailure)

    /** Locally stored KDF parameters, as [unlock] would read them. */
    private fun localParams(): Kdf.Params {
        val algo = credentials.kdfAlgorithm ?: Kdf.Params.Algorithm.PBKDF2_SHA256.name
        return Kdf.Params(
            algorithm = Kdf.Params.Algorithm.fromStored(algo),
            iterations = credentials.kdfIterations,
            memoryKiB = credentials.kdfMemoryKib,
            parallelism = credentials.kdfParallelism,
        )
    }

    /** Zero the derived key. Called on auto-lock, backgrounding, and logout. */
    fun lock() {
        encKey?.fill(0)
        encKey = null
        publishedVault = null
    }

    suspend fun logout() {
        withContext(Dispatchers.IO) {
            runCatching { api.logout() }
        }
        lock()
        credentials.clearAll()
    }

    // ---- Sync -------------------------------------------------------------

    sealed class PullResult {
        data class Loaded(val vault: Vault, val revision: Int) : PullResult()
        object Empty : PullResult()
    }

    suspend fun pull(): Result<PullResult> = withContext(Dispatchers.IO) {
        runCatching {
            requireValidKeys()
            val response = api.getBlob().unwrapOrThrow()
            val userId = credentials.userId
                ?: throw IllegalStateException("Not logged in")

            val payload = response.ciphertext
            if (payload.isNullOrBlank()) {
                credentials.localRevision = response.revision
                return@runCatching PullResult.Empty
            }

            val key = encKey!!
            val blob = payload.decode()
            val plain = try {
                VaultCipher.decrypt(
                    blob = blob,
                    key = key,
                    // AAD uses the revision the blob is *currently* stored at.
                    additionalData = VaultCipher.accountContext(userId, response.revision),
                )
            } catch (t: GeneralSecurityException) {
                // The stored blob no longer decrypts under our key, which is
                // what another device migrating the KDF or changing the
                // password looks like from here. Flag it so the next password
                // unlock adopts the server's parameters instead of failing
                // the same way forever.
                credentials.paramsStale = true
                throw t
            }
            val vault = try {
                Vault.deserialize(plain)
            } catch (t: Exception) {
                credentials.paramsStale = true
                throw t
            } finally {
                plain.fill(0)
            }
            credentials.localRevision = response.revision
            PullResult.Loaded(vault.copy(revision = response.revision), response.revision)
        }
    }.onFailure(::noteAuthFailure)

    sealed class PushResult {
        data class Success(val revision: Int) : PushResult()
        data class Conflict(val serverRevision: Int, val serverCiphertext: String?) : PushResult()
    }

    suspend fun push(vault: Vault): Result<PushResult> = withContext(Dispatchers.IO) {
        runCatching {
            requireValidKeys()
            val userId = credentials.userId
                ?: throw IllegalStateException("Not logged in")
            val baseRevision = credentials.localRevision

            val key = encKey!!
            val plain = vault.serialize()
            val blob = try {
                VaultCipher.encrypt(
                    plaintext = plain,
                    key = key,
                    // AAD uses the revision this blob is *about to become*.
                    additionalData = VaultCipher.accountContext(userId, baseRevision + 1),
                )
            } finally {
                plain.fill(0)
            }

            val response = api.putBlob(
                PutBlobRequest(ciphertext = blob.encode(), baseRevision = baseRevision)
            )

            if (response.code() == 409) {
                val body = response.errorBody()?.string()
                val conflict = runCatching {
                    CONFLICT_JSON.decodeFromString(
                        com.sellerbot.ciphervault.sync.PutBlobResponse.serializer(),
                        body ?: "",
                    )
                }.getOrNull()

                return@runCatching PushResult.Conflict(
                    serverRevision = conflict?.revision ?: baseRevision,
                    serverCiphertext = conflict?.ciphertext,
                )
            }

            val ok = response.unwrapOrThrow()
            val newRevision = ok.revision
                ?: throw VaultApiException(response.code(), "bad_response", "Missing revision")
            credentials.localRevision = newRevision
            PushResult.Success(newRevision)
        }
    }.onFailure(::noteAuthFailure)

    // ---- Helpers ----------------------------------------------------------

    private fun requireValidKeys() {
        if (encKey == null) throw IllegalStateException("Vault is locked")
    }

    /**
     * PBKDF2 or Argon2id then HKDF-expand into the two independent sub-keys.
     * Returns them so the caller can zero the master key immediately.
     */
    @Throws(GeneralSecurityException::class)
    private fun derive(password: CharArray, salt: ByteArray, params: Kdf.Params): Pair<ByteArray, ByteArray> {
        val master = Kdf.derive(password, salt, params)
        return try {
            val derivedAuth = Hkdf.authKey(master)
            val derivedEnc = Hkdf.encryptionKey(master)
            derivedAuth to derivedEnc
        } catch (e: GeneralSecurityException) {
            throw IllegalStateException("Key derivation failed", e)
        } finally {
            master.fill(0)
        }
    }

    // `java.util.Base64` rather than `android.util.Base64`: the platform
    // class is a stub in unit tests and throws "not mocked", which is what
    // kept the unlock path — the security-critical one — untestable. The
    // java.util encoder has been in Android since API 26, the minSdk here.
    private fun ByteArray.encode(): String =
        Base64.getEncoder().encodeToString(this)

    private fun String.decode(): ByteArray =
        Base64.getDecoder().decode(this)

    /**
     * Hex of `sha256(authKey)`, in the lowercase form the server also uses.
     *
     * The auth sub-key itself is never written anywhere — only this digest.
     */
    private fun hashHex(authKey: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(authKey)
            .joinToString(separator = "") { "%02x".format(it) }

    companion object {
        /** Allocated once: a conflict can be hit repeatedly during retries. */
        private val CONFLICT_JSON = kotlinx.serialization.json.Json {
            ignoreUnknownKeys = true
        }
    }
}