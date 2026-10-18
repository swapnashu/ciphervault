package com.sellerbot.ciphervault.repo

import com.sellerbot.ciphervault.crypto.Hkdf
import com.sellerbot.ciphervault.crypto.Kdf
import com.sellerbot.ciphervault.sync.AuditResponse
import com.sellerbot.ciphervault.sync.BlobResponse
import com.sellerbot.ciphervault.sync.ChangePasswordResponse
import com.sellerbot.ciphervault.sync.HealthResponse
import com.sellerbot.ciphervault.sync.KdfChangeRequest
import com.sellerbot.ciphervault.sync.LoginRequest
import com.sellerbot.ciphervault.sync.LoginResponse
import com.sellerbot.ciphervault.sync.MigrateKdfResponse
import com.sellerbot.ciphervault.sync.PreloginRequest
import com.sellerbot.ciphervault.sync.PreloginResponse
import com.sellerbot.ciphervault.sync.PutBlobRequest
import com.sellerbot.ciphervault.sync.PutBlobResponse
import com.sellerbot.ciphervault.sync.RegisterRequest
import com.sellerbot.ciphervault.sync.RegisterResponse
import com.sellerbot.ciphervault.sync.RevokeOthersResponse
import com.sellerbot.ciphervault.sync.SessionsResponse
import com.sellerbot.ciphervault.sync.VaultApi
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response
import java.io.IOException
import java.security.MessageDigest
import java.util.Base64

/**
 * The password-verification contract for a returning device.
 *
 * These exist because the app shipped a version of `unlock()` that derived a
 * key from whatever was typed and installed it without checking it against
 * anything. Any string opened the vault: an account whose blob was still
 * empty never reached the decryptor at all, and one with entries failed
 * *after* the UI had already committed to the unlocked state, so the user sat
 * inside an open vault behind a "Something went wrong" banner.
 *
 * The load-bearing assertion is [wrongPasswordIsRejectedWhenAVerifierIsStored].
 */
class VaultRepositoryTest {

    // ---- The regression this file was written for --------------------------

    @Test
    fun `wrong password is rejected when a verifier is stored`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        // acceptLogin=false: the local mismatch is now followed up with a
        // server check, and the fake must model a server that also rejects
        // the wrong password — which is what makes this a real rejection.
        val repository = VaultRepository(FakeApi(acceptLogin = false), credentials)

        val result = repository.unlock("definitely-not-the-password".toCharArray())

        assertTrue("a wrong password must not unlock", result.isFailure)
        assertFalse("the vault must stay locked", repository.isUnlocked)
        assertNull(repository.copyEncryptionKey())
    }

    @Test
    fun `a rejected re-unlock does not install the new key`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        val repository = VaultRepository(FakeApi(acceptLogin = false), credentials)
        assertTrue(repository.unlock(CORRECT.toCharArray()).isSuccess)
        val accepted = repository.copyEncryptionKey()

        val failed = repository.unlock("wrong".toCharArray())

        assertTrue(failed.isFailure)
        // The vault was already open before this attempt, so it stays open —
        // a typo must not lock someone out of work in progress. What matters
        // is that the key derived from the rejected password was not swapped
        // in, and that no copy of it survives.
        assertArrayEquals("the accepted key must be left alone", accepted, repository.copyEncryptionKey())
    }

    @Test
    fun `the rejection carries a user facing message`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        val repository = VaultRepository(FakeApi(acceptLogin = false), credentials)

        val message = repository.unlock("wrong".toCharArray()).exceptionOrNull()?.message

        assertEquals("Email or password is incorrect", message)
    }

    // ---- The happy path still works ----------------------------------------

    @Test
    fun `correct password unlocks`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        val repository = VaultRepository(FakeApi(), credentials)

        val result = repository.unlock(CORRECT.toCharArray())

        assertTrue(result.isSuccess)
        assertTrue(repository.isUnlocked)
        assertEquals(32, repository.copyEncryptionKey()?.size)
    }

    @Test
    fun `unlocking does not call the server when a verifier is stored`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        val api = FakeApi()
        val repository = VaultRepository(api, credentials)

        repository.unlock(CORRECT.toCharArray())

        assertEquals("local unlock must stay offline", 0, api.loginCalls)
    }

    // ---- Legacy installs, which have no local verifier yet ------------------

    @Test
    fun `legacy install rejects a wrong password via the server`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        credentials.authKeyVerifierHex = null // a pre-verifier install
        val repository = VaultRepository(FakeApi(acceptLogin = false), credentials)

        val result = repository.unlock("wrong".toCharArray())

        assertTrue(result.isFailure)
        assertFalse(repository.isUnlocked)
    }

    @Test
    fun `legacy install unlocks and picks up a verifier`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        credentials.authKeyVerifierHex = null
        val api = FakeApi(acceptLogin = true)
        val repository = VaultRepository(api, credentials)

        val result = repository.unlock(CORRECT.toCharArray())

        assertTrue(result.isSuccess)
        assertTrue(repository.isUnlocked)
        assertEquals(1, api.loginCalls)
        assertEquals(verifierFor(CORRECT, credentials), credentials.authKeyVerifierHex)
    }

    @Test
    fun `legacy install stops calling the server once the verifier is stored`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        credentials.authKeyVerifierHex = null
        val api = FakeApi(acceptLogin = true)
        val repository = VaultRepository(api, credentials)

        repository.unlock(CORRECT.toCharArray())
        repository.lock()
        repository.unlock(CORRECT.toCharArray())

        assertEquals("only the first unlock needs the network", 1, api.loginCalls)
    }

    // ---- Stale copies: another device rotated the key material ------------

    @Test
    fun `a stale local copy relinks to the server instead of failing`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        // Another device rotated the verifier; this device holds the old pair.
        credentials.authKeyVerifierHex = verifierFor("rotated elsewhere", credentials)
        credentials.sessionToken = "stale-session"
        val api = FakeApi(acceptLogin = true)
        val repository = VaultRepository(api, credentials)

        val result = repository.unlock(CORRECT.toCharArray())

        assertTrue(result.isSuccess)
        assertTrue(repository.isUnlocked)
        assertEquals("relink proves the password with one login", 1, api.loginCalls)
        assertEquals("a fresh session replaces the stale one", "session-token", credentials.sessionToken)
        assertEquals(verifierFor(CORRECT, credentials), credentials.authKeyVerifierHex)
        assertFalse(credentials.paramsStale)
        assertArrayEquals(encKeyFor(CORRECT, credentials), repository.copyEncryptionKey())
    }

    @Test
    fun `unlock migrates a PBKDF2 account to the server's memory-hard default`() = runBlocking {
        val credentials = installedAccount(password = CORRECT).apply {
            sessionToken = "session-token"
            wrappedVaultKeyBase64 = "stale-biometric-wrap"
        }
        val beforeSalt = credentials.kdfSaltBase64
        val beforeKey = encKeyFor(CORRECT, credentials)
        val api = FakeApi(
            lowKdfDefault = true,
            migrateResult = Response.success(MigrateKdfResponse(changed = true, revision = 2)),
        )
        val repository = VaultRepository(api, credentials)

        val result = repository.unlock(CORRECT.toCharArray())

        assertTrue(result.isSuccess)
        assertTrue(repository.isUnlocked)
        assertEquals("the migration is attempted exactly once", 1, api.migrateCalls)
        assertEquals(Kdf.Params.Algorithm.ARGON2ID.name, credentials.kdfAlgorithm)
        assertTrue("the salt must rotate", credentials.kdfSaltBase64 != beforeSalt)
        assertEquals(2, credentials.localRevision)
        assertNull(
            "the old biometric wrap cannot open the migrated vault",
            credentials.wrappedVaultKeyBase64,
        )
        assertFalse(credentials.paramsStale)
        assertFalse(
            "the pre-migration key must not survive",
            beforeKey.contentEquals(repository.copyEncryptionKey()),
        )
    }

    @Test
    fun `a failed migration never fails the unlock`() = runBlocking {
        val credentials = installedAccount(password = CORRECT).apply {
            sessionToken = "session-token"
        }
        val beforeSalt = credentials.kdfSaltBase64
        val api = FakeApi(lowKdfDefault = true, migrateFails = true)
        val repository = VaultRepository(api, credentials)

        val result = repository.unlock(CORRECT.toCharArray())

        assertTrue("migration is best effort; the vault still opens", result.isSuccess)
        assertTrue(repository.isUnlocked)
        assertEquals(1, api.migrateCalls)
        assertEquals("a failed attempt adopts nothing", beforeSalt, credentials.kdfSaltBase64)
    }

    @Test
    fun `a lost migration race flags the parameters for the next unlock`() = runBlocking {
        val credentials = installedAccount(password = CORRECT).apply {
            sessionToken = "session-token"
        }
        val api = FakeApi(
            lowKdfDefault = true,
            migrateResult = Response.error(
                409,
                """{"error":"conflict","message":"Vault was modified"}"""
                    .toResponseBody("application/json".toMediaType()),
            ),
        )
        val repository = VaultRepository(api, credentials)

        val result = repository.unlock(CORRECT.toCharArray())

        assertTrue("the race loser still opens the vault", result.isSuccess)
        assertTrue("the winner's parameters must be adopted next time", credentials.paramsStale)
    }

    @Test
    fun `a blob our key cannot decrypt marks the stored parameters stale`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        val api = FakeApi(
            blobCiphertext = Base64.getEncoder().encodeToString(ByteArray(48) { 0x2A }),
        )
        val repository = VaultRepository(api, credentials)
        assertTrue(repository.unlock(CORRECT.toCharArray()).isSuccess)

        val result = repository.pull()

        assertTrue(result.isFailure)
        assertTrue("the next unlock must relink instead of failing the same way", credentials.paramsStale)
    }

    // ---- Registration and login record the verifier --------------------------

    // Fast PBKDF2 params for tests — avoids slow Argon2id in pure Java.
    private val testParams = Kdf.Params(
        algorithm = Kdf.Params.Algorithm.PBKDF2_SHA256,
        iterations = Kdf.MIN_PBKDF2_ITERATIONS,
    )

    @Test
    fun `register stores the verifier`() = runBlocking {
        val credentials = FakeCredentials()
        val repository = VaultRepository(FakeApi(), credentials)

        repository.register(EMAIL, CORRECT.toCharArray(), testParams)

        assertEquals(verifierFor(CORRECT, credentials), credentials.authKeyVerifierHex)
    }

    @Test
    fun `registration against a PBKDF2-era server submits PBKDF2 defaults`() = runBlocking {
        val repository = VaultRepository(FakeApi(), FakeCredentials())

        val params = repository.registrationParams()

        assertEquals(Kdf.Params.Algorithm.PBKDF2_SHA256, params.algorithm)
        assertEquals(Kdf.DEFAULT_ITERATIONS, params.iterations)
    }

    @Test
    fun `registration against a current server submits the Argon2id defaults`() = runBlocking {
        val repository = VaultRepository(FakeApi(lowKdfDefault = true), FakeCredentials())

        val params = repository.registrationParams()

        assertEquals(Kdf.Params.Algorithm.ARGON2ID, params.algorithm)
        assertEquals(Kdf.DEFAULT_ARGON2_PASSES, params.iterations)
        assertEquals(Kdf.DEFAULT_ARGON2_MEMORY_KIB, params.memoryKiB)
        assertEquals(Kdf.DEFAULT_ARGON2_LANES, params.parallelism)
    }

    @Test
    fun `login stores the verifier`() = runBlocking {
        val credentials = FakeCredentials()
        val repository = VaultRepository(FakeApi(), credentials)

        // login() uses prelogin from server; our FakeApi returns PBKDF2.
        repository.login(EMAIL, CORRECT.toCharArray(), device = null)

        assertEquals(verifierFor(CORRECT, credentials), credentials.authKeyVerifierHex)
    }

    @Test
    fun `the stored value is a hash not the auth sub-key`() = runBlocking {
        val credentials = installedAccount(password = CORRECT)
        val stored = credentials.authKeyVerifierHex!!

        assertEquals("a verifier is a SHA-256 digest, so 64 hex chars", 64, stored.length)
        assertTrue(stored.all { it in "0123456789abcdef" })
    }

    // ---- Fixtures -------------------------------------------------------------

    private val salt = ByteArray(16) { it.toByte() }

    /**
     * At [Kdf.MIN_PBKDF2_ITERATIONS] rather than the production 600,000. Lower is
     * rejected outright by `Kdf.Params` — by design — so the floor is the
     * cheapest a fixture is allowed to be.
     */
    private val iterations = Kdf.MIN_PBKDF2_ITERATIONS

    /**
     * A device that has already registered: email, salt, iteration count and
     * the server's auth verifier hash, but no session and no in-memory key.
     */
    private fun installedAccount(password: String): FakeCredentials {
        val credentials = FakeCredentials().apply {
            userEmail = EMAIL
            userId = USER_ID
            kdfSaltBase64 = Base64.getEncoder().encodeToString(salt)
            kdfIterations = iterations
            kdfAlgorithm = "PBKDF2_SHA256"
            authKeyVerifierHex = verifierFor(password, this)
        }
        return credentials
    }

    /** Mirrors `VaultRepository.derive` + `hashHex`, to build a fixture. */
    private fun verifierFor(password: String, credentials: FakeCredentials): String {
        val saltBytes = Base64.getDecoder().decode(credentials.kdfSaltBase64!!)
        val master = Kdf.derive(
            password.toCharArray(),
            saltBytes,
            Kdf.Params(
                algorithm = Kdf.Params.Algorithm.PBKDF2_SHA256,
                iterations = credentials.kdfIterations,
            ),
        )
        return try {
            val authKey = Hkdf.authKey(master)
            MessageDigest.getInstance("SHA-256")
                .digest(authKey)
                .joinToString(separator = "") { "%02x".format(it) }
        } finally {
            master.fill(0)
        }
    }

    /** Mirrors `VaultRepository.derive`, keeping the encryption sub-key. */
    private fun encKeyFor(password: String, credentials: FakeCredentials): ByteArray {
        val saltBytes = Base64.getDecoder().decode(credentials.kdfSaltBase64!!)
        val master = Kdf.derive(
            password.toCharArray(),
            saltBytes,
            Kdf.Params(
                algorithm = Kdf.Params.Algorithm.PBKDF2_SHA256,
                iterations = credentials.kdfIterations,
            ),
        )
        return try {
            Hkdf.encryptionKey(master)
        } finally {
            master.fill(0)
        }
    }

    private companion object {
        const val EMAIL = "test@example.com"
        const val USER_ID = "user-1"
        const val CORRECT = "correct horse battery staple"
    }

    private class FakeCredentials : CredentialStore {
        override var userEmail: String? = null
        override var userId: String? = null
        override var sessionToken: String? = null
        override var kdfSaltBase64: String? = null
        override var kdfIterations: Int = Kdf.MIN_PBKDF2_ITERATIONS
        override var kdfAlgorithm: String? = null
        override var kdfMemoryKib: Int = Kdf.DEFAULT_ARGON2_MEMORY_KIB
        override var kdfParallelism: Int = Kdf.DEFAULT_ARGON2_LANES
        override var localRevision: Int = 0
        override var wrappedVaultKeyBase64: String? = null
        override var authKeyVerifierHex: String? = null
        override var paramsStale: Boolean = false

        override fun hasSession(): Boolean = !sessionToken.isNullOrBlank()

        override fun clearAll() {
            userEmail = null
            userId = null
            sessionToken = null
            kdfSaltBase64 = null
            kdfAlgorithm = null
            wrappedVaultKeyBase64 = null
            authKeyVerifierHex = null
            paramsStale = false
        }
    }

    /**
     * @param acceptLogin when false, replies 401 the way the server does for a
     *        password it does not recognise. The repository cannot tell this
     *        apart from the real thing, which is the point.
     * @param lowKdfDefault reports a memory-hard KDF default (Argon2id passes,
     *        far below any PBKDF2 round count), which is what arms
     *        `maybeMigrate` for a PBKDF2 account.
     * @param migrateResult the migrate-kdf reply; defaults to "not changed".
     * @param migrateFails makes the migrate-kdf call fail like an unreachable
     *        network, for the best-effort contract.
     * @param blobCiphertext returned as the stored vault blob.
     */
    private class FakeApi(
        private val acceptLogin: Boolean = true,
        private val lowKdfDefault: Boolean = false,
        private val migrateResult: Response<MigrateKdfResponse>? = null,
        private val migrateFails: Boolean = false,
        private val blobCiphertext: String? = null,
    ) : VaultApi {

        var loginCalls = 0
            private set

        var migrateCalls = 0
            private set

        override suspend fun health(): Response<HealthResponse> =
            Response.success(
                HealthResponse(
                    "ok",
                    "vault",
                    if (lowKdfDefault) 1_000 else Kdf.DEFAULT_ITERATIONS,
                ),
            )

        override suspend fun prelogin(body: PreloginRequest): Response<PreloginResponse> =
            Response.success(
                PreloginResponse(
                    kdfSalt = Base64.getEncoder().encodeToString(ByteArray(16) { it.toByte() }),
                    kdf = com.sellerbot.ciphervault.sync.KdfParams("PBKDF2_SHA256", Kdf.MIN_PBKDF2_ITERATIONS),
                ),
            )

        override suspend fun register(body: RegisterRequest): Response<RegisterResponse> =
            Response.success(RegisterResponse(USER_ID))

        override suspend fun login(body: LoginRequest): Response<LoginResponse> {
            loginCalls++
            return if (acceptLogin) {
                Response.success(
                    LoginResponse(
                        sessionToken = "session-token",
                        userId = USER_ID,
                        vaultRevision = 1,
                        expiresAt = "2030-01-01T00:00:00Z",
                    ),
                )
            } else {
                Response.error(
                    401,
                    """{"error":"invalid_credentials","message":"Email or password is incorrect"}"""
                        .toResponseBody("application/json".toMediaType()),
                )
            }
        }

        override suspend fun getBlob(): Response<BlobResponse> =
            Response.success(BlobResponse(ciphertext = blobCiphertext, revision = 1))

        override suspend fun putBlob(body: PutBlobRequest): Response<PutBlobResponse> =
            Response.success(PutBlobResponse(revision = 2))

        override suspend fun sessions(): Response<SessionsResponse> =
            Response.success(SessionsResponse(emptyList()))

        override suspend fun revokeOtherSessions(): Response<RevokeOthersResponse> =
            Response.success(RevokeOthersResponse(revoked = 0))

        override suspend fun migrateKdf(body: KdfChangeRequest): Response<MigrateKdfResponse> {
            migrateCalls++
            if (migrateFails) throw IOException("network down")
            return migrateResult ?: Response.success(MigrateKdfResponse(changed = false))
        }

        override suspend fun changePassword(body: KdfChangeRequest): Response<ChangePasswordResponse> =
            Response.success(ChangePasswordResponse(changed = true, revision = 2, revokedSessions = 0))

        override suspend fun audit(limit: Int): Response<AuditResponse> =
            Response.success(AuditResponse(total = 0, events = emptyList()))

        override suspend fun logout(): Response<Void> = Response.success(null)
    }
}
