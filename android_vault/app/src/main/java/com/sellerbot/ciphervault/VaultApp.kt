package com.sellerbot.ciphervault

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Handler
import android.os.Looper
import com.sellerbot.ciphervault.crypto.Kdf
import com.sellerbot.ciphervault.repo.CredentialStore
import com.sellerbot.ciphervault.repo.EncryptedCredentialStore
import com.sellerbot.ciphervault.repo.VaultRepository
import com.sellerbot.ciphervault.security.AppSettings
import com.sellerbot.ciphervault.security.KeystoreManager
import com.sellerbot.ciphervault.sync.VaultApi
import com.sellerbot.ciphervault.ui.util.SecureClipboard

/**
 * Application entry point and the app's tiny service container.
 *
 * Deliberately not a DI framework: there are four objects, wiring them by
 * hand is obvious, and adding Hilt to a project that cannot be build-tested
 * here would be a dependency nobody has verified resolves.
 *
 * Note that the master key is *not* a singleton living here. It is derived on
 * demand, held only in memory for the length of an unlocked session, and
 * zeroed on lock by [VaultRepository.lock].
 */
class VaultApp : Application() {

    /** Keystore-backed keys for biometric-gated unlock. */
    val keystore: KeystoreManager by lazy { KeystoreManager() }

    /** Device-local credentials (session token, salt, revision). */
    val credentials: CredentialStore by lazy { EncryptedCredentialStore(this) }

    /** Non-secret preferences: biometric strength, clipboard timeout. */
    val settings: AppSettings by lazy { AppSettings(this) }

    /** HTTP client, with the session token supplied lazily per request. */
    val api: VaultApi by lazy {
        VaultApi.create(
            tokenProvider = { credentials.sessionToken },
            onTokenRotated = { newToken -> credentials.sessionToken = newToken }
        )
    }

    /** Key derivation + encryption + sync orchestration. */
    val repository: VaultRepository by lazy {
        VaultRepository(api, credentials)
    }

    /** KDF parameters used for new accounts. */
    val defaultKdfParams: Kdf.Params = Kdf.Params()

    /** Lock the vault when the screen turns off (user presses power button). */
    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_OFF) {
                repository.lock()
            }
        }
    }

    /** Delay before locking after UI is hidden (30 seconds grace for quick app switches). */
    private val backgroundLockDelayMs = 30_000L
    private val backgroundLockHandler = Handler(Looper.getMainLooper())
    private val backgroundLockRunnable = Runnable { repository.lock() }

    override fun onCreate() {
        super.onCreate()
        instance = this
        // Read once at startup: a wipe armed against an old timeout would
        // fire at the old time regardless, so switching it mid-session would
        // only be half-true.
        SecureClipboard.CLEAR_AFTER_MS = settings.clipboardClearSeconds * 1000L

        // Lock on screen off so a pocket-lock or power-button press secures the vault.
        registerReceiver(screenOffReceiver, IntentFilter(Intent.ACTION_SCREEN_OFF))
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        when (level) {
            TRIM_MEMORY_UI_HIDDEN -> {
                // User switched away from the app. Schedule a delayed lock
                // so quick app switches (e.g. checking a 2FA code in another app)
                // don't force re-authentication, but the vault will lock if
                // the user stays away.
                backgroundLockHandler.postDelayed(backgroundLockRunnable, backgroundLockDelayMs)
            }
            TRIM_MEMORY_BACKGROUND -> {
                // Process is in the background but not yet hidden. Lock immediately.
                backgroundLockHandler.removeCallbacks(backgroundLockRunnable)
                repository.lock()
            }
            TRIM_MEMORY_RUNNING_LOW, TRIM_MEMORY_RUNNING_CRITICAL, TRIM_MEMORY_MODERATE -> {
                // Genuine memory pressure. Cancel any pending delayed lock and lock immediately.
                backgroundLockHandler.removeCallbacks(backgroundLockRunnable)
                repository.lock()
            }
        }
    }

    override fun onTerminate() {
        super.onTerminate()
        backgroundLockHandler.removeCallbacks(backgroundLockRunnable)
        unregisterReceiver(screenOffReceiver)
    }

    companion object {
        lateinit var instance: VaultApp
            private set

        /** Best-effort zeroing. The JVM gives no guarantees, but it helps. */
        fun ByteArray.zero() {
            fill(0)
        }
    }
}
