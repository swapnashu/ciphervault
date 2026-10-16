package com.sellerbot.ciphervault.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.sellerbot.ciphervault.repo.VaultRepository
import com.sellerbot.ciphervault.sync.VaultApiException
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * The vault's lifecycle as the UI sees it.
 *
 * `Setup` and `Locked` are deliberately separate: a device with no account
 * must not be offered "use biometrics", and a device with an account must not
 * be offered "create account". Conflating them is how password managers end
 * up with a button that silently creates a second empty vault.
 */
sealed class VaultUiState {
    /** First frame, before we know whether this device has an account. */
    data object Loading : VaultUiState()

    /** No local account: offer register, or log in to an existing one. */
    data class Setup(
        val busy: Boolean = false,
        val error: String? = null,
    ) : VaultUiState()

    /** Account present but the master key is not in memory. */
    data class Locked(
        val busy: Boolean = false,
        val error: String? = null,
        /** True when a wrapped key exists and the device can satisfy BIOMETRIC_STRONG. */
        val biometricAvailable: Boolean = false,
        /** Shown as a hint so the user knows which vault they are opening. */
        val userEmailHint: String? = null,
    ) : VaultUiState()

    data class Unlocked(
        val vault: com.sellerbot.ciphervault.model.Vault,
        val syncing: Boolean = false,
        val error: String? = null,
        /**
         * True only once a pull has actually returned the server's snapshot.
         *
         * The shell is shown before that pull completes (so the unlock is
         * instant), which means the vault in [vault] may still be the empty
         * placeholder from `refreshAfterUnlock()`. Pushing an edit built on
         * that placeholder would replace the whole server blob with one entry
         * and destroy everything else, so edits are refused until this is
         * true.
         */
        val loaded: Boolean = false,
    ) : VaultUiState()

    val isLoading: Boolean get() = this is Loading
}

class VaultViewModel(
    private val repository: VaultRepository,
    private val biometricAvailable: () -> Boolean,
) : ViewModel() {

    private val _state = MutableStateFlow<VaultUiState>(VaultUiState.Loading)
    val state: StateFlow<VaultUiState> = _state.asStateFlow()

    /**
     * A parsed `otpauth://` deep link waiting to become a vault entry.
     *
     * Deliberately *not* carried through navigation arguments: those are
     * written into a Bundle and survive in saved state, and a TOTP seed has
     * no business being persisted in plaintext by the framework.
     *
     * The algorithm/digits/period ride along for the same reason the secret
     * does. Dropping them would make the app generate a code that looks
     * valid and is wrong, which is the one failure an authenticator must
     * never have.
     */
    data class PendingOtpauth(
        val secret: String,
        val suggestedTitle: String,
        val algorithm: String,
        val digits: Int,
        val periodSeconds: Int,
    )

    private val _pendingOtpauth = MutableStateFlow<PendingOtpauth?>(null)
    val pendingOtpauth: StateFlow<PendingOtpauth?> = _pendingOtpauth.asStateFlow()

    /**
     * One-shot informational messages (as opposed to [VaultUiState.Unlocked.error],
     * which is sticky until dismissed).
     *
     * A SharedFlow rather than a flag on the state: the snackbar consumer is a
     * composable that may be off-screen when the event fires, and a flag would
     * either re-fire on every recomposition or be cleared out from under the
     * coroutine that is still displaying it.
     */
    private val _notices = MutableSharedFlow<String>(
        extraBufferCapacity = 8,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val notices: SharedFlow<String> = _notices.asSharedFlow()

    /**
     * Accept an `otpauth://totp/...` link.
     *
     * @return false when the URI is not a well-formed TOTP enrolment, so the
     *         caller can decide whether to tell the user.
     */
    fun importOtpauth(uri: String): Boolean {
        val parsed = runCatching { com.sellerbot.ciphervault.crypto.TotpEntry.parseUri(uri) }
            .getOrNull() ?: return false

        _pendingOtpauth.value = PendingOtpauth(
            secret = com.sellerbot.ciphervault.crypto.Base32.encode(parsed.secret),
            suggestedTitle = listOfNotNull(parsed.issuer, parsed.label)
                .filter { it.isNotBlank() }
                .joinToString(" - "),
            algorithm = parsed.algorithm.uriName,
            digits = parsed.digits,
            periodSeconds = parsed.periodSeconds,
        )
        return true
    }

    /** Single-shot: returns the payload once and forgets it. */
    fun takePendingOtpauth(): PendingOtpauth? {
        val pending = _pendingOtpauth.value
        _pendingOtpauth.value = null
        return pending
    }

    init {
        bootstrap()

        // Mirror the unlocked snapshot into the repository for the autofill
        // service, which runs in this process but cannot see this ViewModel.
        //
        // One collector instead of a publish at each of the several places
        // that construct an `Unlocked` state: a missed call would quietly
        // leave autofill serving a stale vault to some other app's login
        // screen, and that failure would be invisible until someone noticed
        // the wrong password being offered.
        viewModelScope.launch {
            state.collect { current ->
                if (current is VaultUiState.Unlocked) {
                    repository.publishVault(current.vault)
                } else {
                    repository.clearPublishedVault()
                }
            }
        }
    }

    private fun bootstrap() {
        _state.value = if (repository.hasLocalAccount) lockedState() else VaultUiState.Setup()
    }

    /** A Locked state that always carries the account hint and bio availability. */
    private fun lockedState(busy: Boolean = false, error: String? = null): VaultUiState.Locked =
        VaultUiState.Locked(
            busy = busy,
            error = error,
            biometricAvailable = biometricAvailable() && repository.hasWrappedBiometricKey,
            userEmailHint = repository.accountEmail,
        )

    // ---- Account creation / login -----------------------------------------

    fun register(email: String, password: CharArray) = runAction(VaultUiState.Setup(busy = true)) {
        repository.register(email, password).getOrThrow()
        refreshAfterUnlock()
    }

    fun login(email: String, password: CharArray) = runAction(VaultUiState.Setup(busy = true)) {
        repository.login(email, password, device = null).getOrThrow()
        refreshAfterUnlock()
    }

    /** Unlock an already-registered device with the master password. */
    fun unlock(password: CharArray) = runAction(lockedState(busy = true)) {
        repository.unlock(password).getOrThrow()
        refreshAfterUnlock()
    }

    /**
     * Called after a successful Class-3 biometric scan, with the encryption
     * key that [com.sellerbot.ciphervault.security.KeystoreManager] unwrapped
     * inside the `BiometricPrompt` callback.
     */
    fun unlockWithEncryptionKey(unwrappedKey: ByteArray) = runAction(
        lockedState(busy = true),
    ) {
        repository.acceptEncryptionKey(unwrappedKey)
        refreshAfterUnlock()
    }

    // ---- Vault operations --------------------------------------------------

    /**
     * Key material for enrolling biometric unlock. Null while locked.
     *
     * Reaching for this is deliberate rather than incidental: enrolment can
     * only happen on an open vault, so a fresh install cannot arm biometrics
     * before the master password has proved itself at least once.
     */
    fun encryptionKeyForBiometricEnrolment(): ByteArray? =
        repository.copyEncryptionKey()

    fun refresh() {
        val current = _state.value
        if (current !is VaultUiState.Unlocked) return
        _state.update { current.copy(syncing = true, error = null) }

        viewModelScope.launch {
            repository.pull()
                .onSuccess { result ->
                    val vault = when (result) {
                        is VaultRepository.PullResult.Loaded -> result.vault
                        VaultRepository.PullResult.Empty ->
                            com.sellerbot.ciphervault.model.Vault.EMPTY
                    }
                    _state.value = VaultUiState.Unlocked(
                        vault = vault,
                        syncing = false,
                        loaded = true,
                    )
                }
                .onFailure { throwable ->
                    _state.update {
                        (it as? VaultUiState.Unlocked)?.copy(
                            syncing = false,
                            error = syncError(throwable),
                        ) ?: it
                    }
                }
        }
    }

    /**
     * The app came back to the foreground.
     *
     * Pulls the latest vault so an edit made on another device appears
     * without the user having to lock and unlock. A cold start and an unlock
     * already pull for themselves, so this only ever covers the case where
     * the process survived a trip to the background and the in-memory vault
     * has quietly gone stale.
     *
     * Skipped while a sync is already running: resuming during an in-flight
     * pull would start a second one, and the first response would then be
     * overwritten by the second for no benefit. Also skipped while locked —
     * there is nothing to decrypt, and unlocking pulls.
     */
    fun onAppResumed() {
        val current = _state.value as? VaultUiState.Unlocked ?: return
        if (current.syncing) return
        refresh()
    }

    fun upsert(entry: com.sellerbot.ciphervault.model.VaultEntry) {
        val current = _state.value as? VaultUiState.Unlocked ?: return
        if (!refuseUnlessLoaded()) return
        val updated = current.vault.withEntry(entry)
        _state.value = current.copy(vault = updated, error = null)
        push(updated)
    }

    fun delete(entryId: String) {
        val current = _state.value as? VaultUiState.Unlocked ?: return
        if (!refuseUnlessLoaded()) return
        val updated = current.vault.withoutEntry(entryId)
        _state.value = current.copy(vault = updated, error = null)
        push(updated)
    }

    /**
     * Refuse a local mutation until the server's snapshot has been pulled.
     *
     * Returns true when the edit may proceed. Without this a pull that fails
     * during unlock leaves the shell showing the empty placeholder, and the
     * first edit written from it would be pushed as the entire vault.
     *
     * Public because the shell calls it before even opening the add form, so
     * the refusal message reaches the banner instead of an empty form.
     */
    fun refuseUnlessLoaded(): Boolean {
        val current = _state.value as? VaultUiState.Unlocked ?: return false
        if (current.loaded) return true
        _state.update {
            (it as? VaultUiState.Unlocked)?.copy(
                syncing = false,
                error = "Your vault hasn't finished loading. Changes will be " +
                    "saved once it syncs - try again in a moment.",
            ) ?: it
        }
        return false
    }

    private fun push(
        vault: com.sellerbot.ciphervault.model.Vault,
        conflictRetries: Int = MAX_CONFLICT_RETRIES,
    ) {
        if (!refuseUnlessLoaded()) return
        _state.update { (it as? VaultUiState.Unlocked)?.copy(syncing = true) ?: it }

        viewModelScope.launch {
            repository.push(vault)
                .onSuccess { result ->
                    when (result) {
                        is VaultRepository.PushResult.Success -> _state.update {
                            (it as? VaultUiState.Unlocked)?.copy(syncing = false) ?: it
                        }
                        is VaultRepository.PushResult.Conflict ->
                            resolveConflict(conflictRetries)
                    }
                }
                .onFailure { throwable ->
                    _state.update {
                        (it as? VaultUiState.Unlocked)?.copy(
                            syncing = false,
                            error = syncError(throwable),
                        ) ?: it
                    }
                }
        }
    }

    /**
     * Another device wrote between our read and our write.
     *
     * Re-pulling and adopting the server snapshot — which is what a plain
     * `refresh()` did — silently discarded the edit the user just made, on a
     * password manager. Instead: pull, union the two snapshots entry by entry,
     * and push again against the fresh revision. Bounded, because every round
     * needs a fresh concurrent write and two devices genuinely fighting would
     * otherwise spin forever.
     */
    private fun resolveConflict(retriesLeft: Int) {
        if (retriesLeft <= 0) {
            // Do not touch the local snapshot: the user's edit stays on screen
            // and unsaved rather than being overwritten by the server's copy.
            _state.update {
                (it as? VaultUiState.Unlocked)?.copy(
                    syncing = false,
                    error = "This vault is being changed on another device. Try again in a moment.",
                ) ?: it
            }
            return
        }

        viewModelScope.launch {
            repository.pull()
                .onSuccess { result ->
                    val remote = (result as? VaultRepository.PullResult.Loaded)?.vault
                        ?: com.sellerbot.ciphervault.model.Vault.EMPTY

                    // Re-read the vault *now*: a further edit may have landed
                    // while the pull was in flight, and that one must survive too.
                    val current = (_state.value as? VaultUiState.Unlocked)?.vault
                        ?: return@onSuccess

                    val merged = current.mergeWith(remote)
                    _state.update {
                        (it as? VaultUiState.Unlocked)?.copy(vault = merged, syncing = false) ?: it
                    }
                    _notices.tryEmit("Merged changes from another device")
                    push(merged, retriesLeft - 1)
                }
                .onFailure { throwable ->
                    _state.update {
                        (it as? VaultUiState.Unlocked)?.copy(
                            syncing = false,
                            error = syncError(throwable),
                        ) ?: it
                    }
                }
        }
    }

    // ---- Session -----------------------------------------------------------

    fun lock() {
        repository.lock()
        _state.value = lockedState()
    }

    fun logout() {
        // The payload belongs to whichever account was open when the link
        // was tapped; it must not follow the user into a different vault.
        _pendingOtpauth.value = null
        viewModelScope.launch {
            repository.logout()
            _state.value = VaultUiState.Setup()
        }
    }

    fun clearError() {
        var retryLoad = false
        _state.update {
            when (it) {
                is VaultUiState.Setup -> it.copy(error = null)
                is VaultUiState.Locked -> it.copy(error = null)
                is VaultUiState.Unlocked -> {
                    // Dismissing the "vault hasn't loaded" banner is the only
                    // in-screen retry we have, so take it.
                    retryLoad = !it.loaded
                    it.copy(error = null)
                }
                VaultUiState.Loading -> it
            }
        }
        if (retryLoad) refresh()
    }

    // ---- Internals ---------------------------------------------------------

    private suspend fun refreshAfterUnlock() {
        // `loaded = false` (the default) is load-bearing: edits are refused
        // until the pull below actually returns the server's snapshot.
        _state.value = VaultUiState.Unlocked(
            vault = com.sellerbot.ciphervault.model.Vault.EMPTY,
            syncing = true,
        )
        refresh()
    }

    /**
     * Run a suspend action with a consistent busy/error envelope so each
     * screen does not have to hand-roll the same three state transitions.
     */
    private fun runAction(busyState: VaultUiState, block: suspend () -> Unit) {
        viewModelScope.launch {
            _state.value = busyState
            try {
                block()
            } catch (t: Throwable) {
                _state.update { current ->
                    when (current) {
                        is VaultUiState.Setup -> current.copy(busy = false, error = readable(t))
                        is VaultUiState.Locked -> current.copy(busy = false, error = readable(t))
                        is VaultUiState.Unlocked -> current.copy(syncing = false, error = readable(t))
                        VaultUiState.Loading -> current
                    }
                }
            }
        }
    }

    /**
     * Server messages are already phrased for users (``Email or password is
     * incorrect``, ``Too many attempts...``), so they are passed through.
     * Raw exceptions are not.
     */
    /**
     * Error text for a *sync* failure.
     *
     * A 401 during sync means the session died, not the password — showing
     * "check your connection" there sends the user to reboot their router.
     * The fix is to lock and unlock with the master password, which
     * re-authenticates against the server.
     */
    private fun syncError(throwable: Throwable): String =
        if (throwable is VaultApiException && throwable.isAuthFailure) {
            "Your session has expired. Lock the vault, then unlock with your " +
                "master password to sign in again."
        } else {
            readable(throwable)
        }

    private fun readable(throwable: Throwable): String = when (throwable) {
        is VaultApiException -> throwable.message
        is IllegalStateException -> throwable.message ?: "Something went wrong"
        // A wrong master password raises this (see VaultRepository.verifyOrUpgrade).
        // Letting it fall through to the catch-all told users their *connection*
        // was at fault when their password was wrong.
        is IllegalArgumentException -> throwable.message ?: "Something went wrong"
        else -> "Something went wrong. Check your connection and try again."
    }

    companion object {
        /**
         * How many pull-merge-push rounds a single conflict may cost before
         * giving up. Three is plenty for two humans on two devices and small
         * enough that an adversarial writer cannot pin a coroutine looping.
         */
        private const val MAX_CONFLICT_RETRIES = 3

        fun factory(
            repository: VaultRepository,
            biometricAvailable: () -> Boolean,
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T =
                VaultViewModel(repository, biometricAvailable) as T
        }
    }
}
