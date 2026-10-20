package com.sellerbot.ciphervault.sync

import com.sellerbot.ciphervault.BuildConfig
import kotlinx.serialization.json.Json
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import okhttp3.CertificatePinner
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.PUT
import retrofit2.http.Query
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Retrofit binding for the vault API.
 *
 * Every call returns [Response] rather than the body directly, because the
 * contract is status-code driven: 401 means re-authenticate, 409 on PUT means
 * merge-and-retry, 429 means back off. Collapsing those into exceptions at
 * the Retrofit layer would lose the distinction the client depends on.
 *
 * Certificate pinning: the client embeds the SHA-256 fingerprint of the
 * production certificate. If the server presents a different cert (MITM),
 * the connection is aborted. The pin is Base64-encoded SPKI.
 */
interface VaultApi {

    @GET("health")
    suspend fun health(): Response<HealthResponse>

    @POST("prelogin")
    suspend fun prelogin(@Body body: PreloginRequest): Response<PreloginResponse>

    @POST("register")
    suspend fun register(@Body body: RegisterRequest): Response<RegisterResponse>

    @POST("login")
    suspend fun login(@Body body: LoginRequest): Response<LoginResponse>

    @GET("blob")
    suspend fun getBlob(): Response<BlobResponse>

    @PUT("blob")
    suspend fun putBlob(@Body body: PutBlobRequest): Response<PutBlobResponse>

    @GET("sessions")
    suspend fun sessions(): Response<SessionsResponse>

    @POST("sessions/revoke-others")
    suspend fun revokeOtherSessions(): Response<RevokeOthersResponse>

    @POST("migrate-kdf")
    suspend fun migrateKdf(@Body body: KdfChangeRequest): Response<MigrateKdfResponse>

    @POST("change-password")
    suspend fun changePassword(@Body body: KdfChangeRequest): Response<ChangePasswordResponse>

    @GET("audit")
    suspend fun audit(@Query("limit") limit: Int = 50): Response<AuditResponse>

    /**
     * 204 No Content. `Response<Void>` rather than `Response<Unit>` because
     * Retrofit's built-in converter only has a built-in path for `Void`.
     */
    @POST("logout")
    suspend fun logout(): Response<Void>

    companion object {
        private val JSON = Json {
            ignoreUnknownKeys = true
            isLenient = false
            // Never log this; only used to decode server errors.
        }

        /**
         * @param tokenProvider read lazily per request so a refreshed session
         *        token does not require rebuilding the client.
         */
        /**
         * @param tokenProvider read lazily per request so a refreshed session
         *        token does not require rebuilding the client.
         * @param onTokenRotated called when the server rotates the session token
         *        (via X-New-Session-Token header). The new token should be stored
         *        and used for subsequent requests.
         */
        fun create(
            baseUrl: String = BuildConfig.API_BASE_URL,
            tokenProvider: () -> String? = { null },
            onTokenRotated: ((String) -> Unit)? = null,
        ): VaultApi {
            val authInterceptor = Interceptor { chain ->
                val token = tokenProvider()
                val request = if (token.isNullOrBlank()) {
                    chain.request()
                } else {
                    chain.request().newBuilder()
                        .header("Authorization", "Bearer $token")
                        .build()
                }
                chain.proceed(request)
            }

            // Interceptor to handle session token rotation from server
            val tokenRotationInterceptor = Interceptor { chain ->
                val response = chain.proceed(chain.request())
                response.header("X-New-Session-Token")?.let { newToken ->
                    onTokenRotated?.invoke(newToken)
                }
                response
            }

            // Never log headers: `Authorization: Bearer <token>` is a
            // live session credential, and logcat is world-readable on a
            // rooted device and via `adb logcat` on a debug build.
            // `Level.NONE` is therefore the only safe setting for
            // HttpLoggingInterceptor here.
            val logging = HttpLoggingInterceptor().apply {
                level = HttpLoggingInterceptor.Level.NONE
            }

            // What debugging actually needs — method, path and status —
            // with no header ever leaving the process.
            val summary = Interceptor { chain ->
                val request = chain.request()
                val started = System.nanoTime()
                val response = chain.proceed(request)
                android.util.Log.d(
                    "CipherVault/API",
                    "${request.method} ${request.url.encodedPath} -> ${response.code} " +
                        "(${(System.nanoTime() - started) / 1_000_000}ms)",
                )
                response
            }

            // Certificate pinning for the production host.
            //
            // A pin is the Base64 SHA-256 of the SPKI. OkHttp accepts the
            // request if *any* pin matches a certificate in the chain the
            // server presents, so listing leaf, intermediate and root keeps
            // us valid across renewals: the leaf alone would brick sync on
            // renewal, and leaf+intermediate would brick it again when Let's
            // Encrypt rolls the intermediate over. The ISRG Root X1 pin is
            // the backup that survives both - it is in every chain served
            // until the root expires (2035-06-04).
            //
            // Pins measured 2026-10-13 from sellerbots.pythonanywhere.com:
            //   leaf         CN=*.pythonanywhere.com   (notAfter 2026-12-20)
            //   intermediate CN=YE2, O=Let's Encrypt
            // Root pin computed 2026-10-15 from the official PEM at
            // https://letsencrypt.org/certs/isrgrootx1.pem
            // (subject CN=ISRG Root X1, notAfter 2035-06-04) - never by
            // hand-copying a published pin string.
            //
            // Refresh the leaf/intermediate when the leaf changes:
            //   openssl s_client -connect sellerbots.pythonanywhere.com:443 \
            //     -servername sellerbots.pythonanywhere.com </dev/null 2>/dev/null |
            //     openssl x509 -pubkey -noout |
            //     openssl pkey -pubin -outform der |
            //     openssl dgst -sha256 -binary | base64
            // Refresh the root the same way whenever Let's Encrypt retires
            // ISRG X1 (re-download the official PEM first):
            //   curl -sSL https://letsencrypt.org/certs/isrgrootx1.pem |
            //     openssl x509 -pubkey -noout |
            //     openssl pkey -pubin -outform der |
            //     openssl dgst -sha256 -binary | base64
            val leafPin =
                "sha256/P9wFyZ9Ri62wXDQgmnMys/27B9MwVsVBcjUOwL4QIIA="
            val intermediatePin =
                "sha256/s/tdAOmUzd8syaTuqfgGvFcn6DzA5Cmb+Vby1ST+U3Y="
            val rootPin =
                "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="
            val certificatePinner = CertificatePinner.Builder()
                .add("sellerbots.pythonanywhere.com", leafPin, intermediatePin, rootPin)
                .build()

            val client = OkHttpClient.Builder()
                .addInterceptor(authInterceptor)
                .addInterceptor(logging)
                .addInterceptor(summary)
                .addInterceptor(tokenRotationInterceptor)
                .certificatePinner(certificatePinner)
                .connectTimeout(20, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build()

            // Retrofit requires a trailing slash on the base URL.
            val normalized = if (baseUrl.endsWith("/")) baseUrl else "$baseUrl/"

            return Retrofit.Builder()
                .baseUrl(normalized)
                .client(client)
                .addConverterFactory(JSON.asConverterFactory("application/json".toMediaType()))
                .build()
                .create(VaultApi::class.java)
        }
    }
}

/**
 * Raised for any non-2xx that carries the server's JSON error body.
 *
 * @property code HTTP status.
 * @property error machine-readable code (``rate_limited``, ``conflict``, ...)
 * @property message human-readable text, safe to show the user.
 */
class VaultApiException(
    val code: Int,
    val error: String,
    override val message: String,
    cause: Throwable? = null,
) : IOException(message, cause) {

    val isRateLimited: Boolean get() = code == 429 || error == ApiErrorBody.RATE_LIMITED
    val isAuthFailure: Boolean get() = code == 401
    val isConflict: Boolean get() = code == 409 || error == ApiErrorBody.CONFLICT
    val isServerDown: Boolean get() = code >= 500

    companion object {
        private val JSON = Json { ignoreUnknownKeys = true }

        /**
         * Turn a non-2xx [Response] into a typed exception, falling back to
         * the status line when the body is not the expected JSON (a proxy
         * error page, for instance).
         */
        fun from(response: Response<*>): VaultApiException {
            val code = response.code()
            val raw = try {
                response.errorBody()?.string()
            } catch (_: Exception) {
                null
            }

            val parsed = raw?.let {
                try {
                    JSON.decodeFromString(ApiErrorBody.serializer(), it)
                } catch (_: Exception) {
                    null
                }
            }

            val message = if (parsed?.error == "not_found") {
                // Old server deployments simply don't have the newer routes
                // (audit log, change-password, migrate-kdf, revoke-others).
                // A raw "No such endpoint" would read like a bug, so every
                // such 404 is reported as the server being out of date — the
                // deploy, not the client, is what makes these work.
                "Not supported by this server yet. Update the server, then try again."
            } else {
                parsed?.message ?: "Request failed (HTTP $code)"
            }

            return VaultApiException(
                code = code,
                error = parsed?.error ?: "http_$code",
                message = message,
            )
        }
    }
}

/**
 * Unwrap a successful response, or throw [VaultApiException].
 * 409 is returned as-is by the caller for blob writes, so it is *not* unwrapped here.
 */
internal fun <T> Response<T>.unwrapOrThrow(): T {
    if (isSuccessful) {
        return body() ?: throw VaultApiException(code(), "empty_body", "Server returned no body")
    }
    throw VaultApiException.from(this)
}
