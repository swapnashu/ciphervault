package com.sellerbot.ciphervault.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.Toast
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.VaultApp
import com.sellerbot.ciphervault.model.EntryType
import com.sellerbot.ciphervault.model.VaultEntry
import com.sellerbot.ciphervault.repo.VaultRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Fills logins from the vault into other apps, and offers to save new ones.
 *
 * Runs in this app's process but in its own component, which is why it reads
 * the decrypted vault from [VaultRepository.openVault] rather than from the
 * ViewModel - and why that snapshot is dropped by `VaultRepository.lock()`
 * rather than by anything UI-owned, so backgrounding the app clears it too.
 *
 * While the vault is locked this returns `null` rather than failing: the
 * framework treats `onSuccess(null)` as "I have nothing for this screen" and
 * simply shows no picker. `onFailure` exists for retryable errors, but it was
 * broken until Android 10 and minSdk is 26, so it is used only where a retry
 * genuinely helps.
 */
class VaultAutofillService : AutofillService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val app: VaultApp get() = application as VaultApp

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    // ---- Fill --------------------------------------------------------------

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val response = try {
            val context = request.fillContexts.lastOrNull()
            if (context == null) {
                callback.onSuccess(null)
                return
            }
            val screen = parseScreen(context.structure)
            buildResponse(screen, app.repository.openVault)
        } catch (t: Throwable) {
            // A malformed structure from some other app must not be able to
            // take down the service; the next request will be tried afresh.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                callback.onFailure("CipherVault could not read this screen")
            } else {
                callback.onSuccess(null)
            }
            return
        }
        callback.onSuccess(response)
    }

    /**
     * Assemble the picker. Returns null when there is nothing worth showing -
     * locked vault, no fillable fields, or no stored login at all.
     */
    private fun buildResponse(screen: Screen, vault: com.sellerbot.ciphervault.model.Vault?): FillResponse? {
        if (vault == null) return null

        val passwordFields = screen.fields.filter { it.isPassword }
        val usernameFields = screen.fields.filter { it.isUsername }
        if (passwordFields.isEmpty() && usernameFields.isEmpty()) return null

        // Prefer whichever field the user is actually in: on a change-password
        // form the first box in tree order is not necessarily the live one.
        val preferredUsername = usernameFields.firstOrNull { it.focused } ?: usernameFields.firstOrNull()
        val preferredPassword = passwordFields.firstOrNull { it.focused } ?: passwordFields.firstOrNull()

        val target = FillTarget(
            webDomain = screen.webDomains.firstOrNull(),
            packageNames = screen.packageNames,
            focusedUsername = preferredUsername?.value,
        )

        val ranked = AutofillMatcher.rank(vault.liveEntries, target)

        // Deliberately does NOT bail out when nothing matches. The save offer
        // is carried on this very response, and a site we have never seen
        // before is precisely the case where saving matters most.
        if (ranked.isEmpty() && passwordFields.isEmpty()) return null

        val response = FillResponse.Builder()
        for (entry in ranked) {
            val dataset = buildDataset(entry, preferredUsername, preferredPassword)
                ?: continue
            response.addDataset(dataset)
        }

        if (passwordFields.isNotEmpty()) {
            val saveType = if (usernameFields.isNotEmpty()) {
                SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME
            } else {
                SaveInfo.SAVE_DATA_TYPE_PASSWORD
            }
            response.setSaveInfo(
                SaveInfo.Builder(saveType, passwordFields.map { it.autofillId }.toTypedArray()).build(),
            )
        }

        return response.build()
    }

    @Suppress("DEPRECATION") // Dataset.Builder(RemoteViews) is the API 26 form;
    // the no-arg builder only arrived in API 30, below our compile target's floor.
    private fun buildDataset(
        entry: VaultEntry,
        usernameField: Field?,
        passwordField: Field?,
    ): Dataset? {
        val title = entry.title.ifBlank { entry.username ?: "" }
        val subtitle = entry.username ?: entry.url.orEmpty()

        val builder = Dataset.Builder(presentation(title, subtitle))
        var assigned = 0

        if (usernameField != null && !entry.username.isNullOrBlank()) {
            builder.setValue(usernameField.autofillId, AutofillValue.forText(entry.username))
            assigned++
        }
        if (passwordField != null && !entry.password.isNullOrBlank()) {
            builder.setValue(passwordField.autofillId, AutofillValue.forText(entry.password))
            assigned++
        }

        // A dataset with no values is rejected by the builder and would abort
        // the whole response, so drop entries that match neither field.
        if (assigned == 0) return null
        return builder.build()
    }

    private fun presentation(title: String, subtitle: String): RemoteViews =
        RemoteViews(packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.autofill_title, title)
            setTextViewText(R.id.autofill_subtitle, subtitle)
        }

    // ---- Save --------------------------------------------------------------

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        scope.launch {
            val repository = app.repository
            val vault = repository.openVault
            if (vault == null) {
                callback.onFailure(getString(R.string.autofill_save_locked))
                return@launch
            }

            // SaveRequest exposes the structure only through its fill
            // contexts; unlike FillRequest it has no getStructure().
            val fillContext = request.fillContexts.lastOrNull()
            if (fillContext == null) {
                callback.onFailure("CipherVault received no screen to save from")
                return@launch
            }
            val screen = parseScreen(fillContext.structure)
            val password = screen.fields.firstOrNull { it.isPassword }?.value?.takeIf { it.isNotBlank() }
            if (password == null) {
                callback.onSuccess()
                return@launch
            }

            val username = screen.fields.firstOrNull { it.isUsername }?.value?.takeIf { it.isNotBlank() }
            val domain = screen.webDomains.firstOrNull()
            val entry = existingEntry(vault, domain, screen, username) ?: VaultEntry(
                type = EntryType.LOGIN,
                title = domain ?: screen.packageNames.firstOrNull() ?: getString(R.string.app_name),
                username = username,
                password = password,
                url = urlFor(domain, screen),
            )

            val current = vault.entries.firstOrNull { it.id == entry.id }
            val toSave = if (current == null) {
                entry
            } else {
                entry.copy(password = password, updatedAt = System.currentTimeMillis())
            }

            val ok = saveWithMerge(repository, vault, toSave)
            if (ok) {
                // The system's own save confirmation is not guaranteed to
                // appear, so say so from our side of the handoff.
                withContext(Dispatchers.Main) {
                    Toast.makeText(applicationContext, R.string.autofill_saved, Toast.LENGTH_SHORT)
                        .show()
                }
                callback.onSuccess()
            } else {
                callback.onFailure(getString(R.string.autofill_save_failed))
            }
        }
    }

    /**
     * Reuse the login already stored for this site and user instead of
     * creating a twin on every password change - a vault that accumulates
     * five copies of the same account is worse than no save prompt at all.
     */
    private fun existingEntry(
        vault: com.sellerbot.ciphervault.model.Vault,
        domain: String?,
        screen: Screen,
        username: String?,
    ): VaultEntry? {
        val packageUrl = urlFor(domain, screen)
        return vault.liveEntries.firstOrNull { entry ->
            entry.type == EntryType.LOGIN &&
                (entry.username ?: "") == (username ?: "") &&
                (
                    (domain != null && Domains.matches(entry.url, domain)) ||
                        (packageUrl != null && Domains.matches(entry.url, packageUrl))
                    )
        }
    }

    private fun urlFor(domain: String?, screen: Screen): String? = when {
        domain != null -> "https://$domain"
        else -> screen.packageNames.firstOrNull()
            ?.let { Domains.hostFromPackageName(it) }
            ?.let { "https://$it" }
    }

    /**
     * Push, merging on conflict.
     *
     * The UI may have pushed between the snapshot we read and our write; the
     * same 409 handling the ViewModel does, so a save from the autofill
     * picker cannot silently discard an edit made on the vault screen.
     */
    private suspend fun saveWithMerge(
        repository: VaultRepository,
        base: com.sellerbot.ciphervault.model.Vault,
        entry: VaultEntry,
    ): Boolean {
        var vault = base.withEntry(entry)
        repeat(MAX_SAVE_RETRIES) {
            when (repository.push(vault).getOrNull()) {
                is VaultRepository.PushResult.Success -> {
                    repository.publishVault(vault)
                    return true
                }

                is VaultRepository.PushResult.Conflict -> {
                    val remote = (repository.pull().getOrNull() as? VaultRepository.PullResult.Loaded)?.vault
                        ?: return false
                    // Re-apply our entry after the merge: unioning two vaults
                    // keeps whichever copy sorts as newer, and the change being
                    // saved right now must be the one that survives.
                    vault = vault.mergeWith(remote).withEntry(entry)
                }

                else -> return false
            }
        }
        return false
    }

    // ---- Structure parsing -------------------------------------------------

    private data class Field(
        val autofillId: AutofillId,
        val isUsername: Boolean,
        val isPassword: Boolean,
        val value: String?,
        val focused: Boolean,
    )

    private data class Screen(
        val fields: List<Field>,
        val webDomains: Set<String>,
        val packageNames: Set<String>,
    )

    private fun parseScreen(structure: AssistStructure): Screen {
        val fields = mutableListOf<Field>()
        val domains = mutableSetOf<String>()
        val packages = mutableSetOf<String>()
        structure.activityComponent?.packageName?.let { if (it.isNotBlank()) packages += it }

        for (index in 0 until structure.windowNodeCount) {
            collect(structure.getWindowNodeAt(index).rootViewNode, fields, domains, packages, depth = 0)
        }
        return Screen(fields, domains, packages)
    }

    /**
     * Depth-capped walk: the structure comes from an arbitrary third-party
     * app, and an unbounded recursion over someone else's view tree is a way
     * to turn one hostile screen into a StackOverflow in our own service.
     */
    private fun collect(
        node: AssistStructure.ViewNode,
        fields: MutableList<Field>,
        domains: MutableSet<String>,
        packages: MutableSet<String>,
        depth: Int,
    ) {
        if (depth > MAX_DEPTH) return

        // Validate and normalise in one step: the domain comes from an app we
        // do not control, and hostOf rejects empty schemes, embedded spaces
        // and absurd lengths before anything downstream compares against it.
        Domains.hostOf(node.webDomain)?.let { domains += it }

        val hints = node.autofillHints?.map { it.lowercase() } ?: emptyList()
        val password = isPasswordField(node, hints)
        val username = !password && isUsernameField(node, hints)

        val autofillId = node.autofillId
        if (autofillId != null && (password || username)) {
            fields += Field(
                autofillId = autofillId,
                isUsername = username,
                isPassword = password,
                value = node.text?.toString(),
                focused = node.isFocused,
            )
        }

        for (index in 0 until node.childCount) {
            collect(node.getChildAt(index), fields, domains, packages, depth + 1)
        }
    }

    private fun isPasswordField(node: AssistStructure.ViewNode, hints: List<String>): Boolean {
        if (hints.any { it == "password" || it == "passwd" || it == "pwd" || it.endsWith("password") }) {
            return true
        }
        val variation = node.inputType and InputType.TYPE_MASK_VARIATION
        return variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
            variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD
    }

    /**
     * Deliberately conservative. A false positive writes a username into a
     * field that was never one, which the user sees immediately and blames on
     * us; a false negative only means one more manual tap.
     */
    private fun isUsernameField(node: AssistStructure.ViewNode, hints: List<String>): Boolean {
        if (hints.any {
                it == "username" || it == "user" || it == "email" ||
                    it == "emailaddress" || it == "phone" || it == "tel"
            }
        ) {
            return true
        }

        val variation = node.inputType and InputType.TYPE_MASK_VARIATION
        if (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
            variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
        ) {
            return true
        }

        val idEntry = node.idEntry?.lowercase() ?: return false
        return USERNAME_ID_TOKENS.any { idEntry.contains(it) }
    }

    private companion object {
        /** Bound on how deep an untrusted view tree may recurse. */
        const val MAX_DEPTH = 64

        /** Bounded like the ViewModel's conflict loop, for the same reason. */
        const val MAX_SAVE_RETRIES = 3

        val USERNAME_ID_TOKENS = listOf("user", "email", "login", "account", "signin")
    }
}
