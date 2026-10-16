package com.sellerbot.ciphervault.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Login
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.VaultApp
import com.sellerbot.ciphervault.security.BiometricGate
import com.sellerbot.ciphervault.sync.AuditEvent
import com.sellerbot.ciphervault.sync.SessionInfo
import com.sellerbot.ciphervault.ui.util.isCipherVaultAutofill
import com.sellerbot.ciphervault.ui.util.openAutofillSettings
import com.sellerbot.ciphervault.ui.theme.BadRed
import com.sellerbot.ciphervault.ui.theme.Gold
import com.sellerbot.ciphervault.ui.theme.GoodGreen
import com.sellerbot.ciphervault.ui.theme.WarnAmber
import kotlinx.coroutines.launch

/**
 * Security and behaviour settings.
 *
 * The biometric and autofill controls used to live behind two dialogs
 * reachable only from the vault's top bar, which made them effectively
 * undiscoverable — and left the fingerprint button absent on a device that
 * had never enrolled, with nothing to explain why. Both are now listed here
 * with their status stated in words.
 */
@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun SettingsScreen(
    encryptionKeyForBiometricEnrolment: () -> ByteArray?,
    biometricEnrolled: Boolean,
    vaultLoadedGate: () -> Boolean,
    onLockVault: () -> Unit,
    onOpenMenu: () -> Unit,
) {
    val context = LocalContext.current
    val app = remember(context) { context.applicationContext as VaultApp }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.nav_settings)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                navigationIcon = {
                    IconButton(onClick = onOpenMenu) {
                        Icon(Icons.Filled.Menu, contentDescription = stringResource(R.string.nav_menu))
                    }
                },
            )
        },
    ) { padding ->

    // Read once, then kept in step locally: CredentialStore is plain
    // SharedPreferences and has no way to notify Compose that it changed.
    var biometricEnabled by remember { mutableStateOf(biometricEnrolled) }
    var allowWeak by remember { mutableStateOf(app.settings.allowWeakBiometrics) }
    var biometricBusy by remember { mutableStateOf(false) }
    var biometricError by remember { mutableStateOf<String?>(null) }

    var autofillEnabled by remember { mutableStateOf(isCipherVaultAutofill(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                autofillEnabled = isCipherVaultAutofill(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    var clipboardSeconds by remember { mutableStateOf(app.settings.clipboardClearSeconds) }

    // ---- Sessions / activity / password change ------------------------------
    val scope = rememberCoroutineScope()
    var sessions by remember { mutableStateOf<List<SessionInfo>?>(null) }
    var sessionsBusy by remember { mutableStateOf(false) }
    var sessionsError by remember { mutableStateOf<String?>(null) }
    var sessionsNotice by remember { mutableStateOf<String?>(null) }
    var activity by remember { mutableStateOf<List<AuditEvent>?>(null) }
    var activityBusy by remember { mutableStateOf(false) }
    var activityError by remember { mutableStateOf<String?>(null) }

    fun loadSessions() {
        scope.launch {
            sessionsBusy = true
            sessionsError = null
            app.repository.activeSessions()
                .onSuccess { sessions = it }
                .onFailure { sessionsError = apiMessage(it) }
            sessionsBusy = false
        }
    }

    fun loadActivity() {
        scope.launch {
            activityBusy = true
            activityError = null
            app.repository.auditEvents(limit = 50)
                .onSuccess { activity = it.events }
                .onFailure { activityError = apiMessage(it) }
            activityBusy = false
        }
    }

    LaunchedEffect(Unit) {
        loadSessions()
        loadActivity()
    }

    var showPasswordDialog by remember { mutableStateOf(false) }
    var currentPassword by remember { mutableStateOf("") }
    var newPassword by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var passwordBusy by remember { mutableStateOf(false) }
    var passwordError by remember { mutableStateOf<String?>(null) }
    var passwordNotice by remember { mutableStateOf<String?>(null) }

    val passwordTitle = stringResource(R.string.settings_change_password)
    val passwordMismatch = stringResource(R.string.settings_password_mismatch)
    val passwordDone = stringResource(R.string.settings_password_change_done)
    val passwordFallbackError = stringResource(R.string.settings_password_change_error)
    val signedOutN = stringResource(R.string.settings_signed_out_n)
    val signedOutNone = stringResource(R.string.settings_signed_out_none)

    fun gate(): BiometricGate? {
        val activity = context as? FragmentActivity ?: return null
        return BiometricGate(
            activity = activity,
            keystore = app.keystore,
            credentials = app.credentials,
            allowWeakBiometrics = allowWeak,
        )
    }

    /**
     * Wrap the open vault's key behind a biometric.
     *
     * The key copy must be zeroed on *every* exit, including user cancel —
     * a prompt can sit open for minutes and there is no reason to leave
     * vault key material on the heap while it does.
     */
    fun enableBiometrics(keyProvider: () -> ByteArray?) {
        val g = gate()
        if (g == null) {
            biometricError = "Biometric unlock is unavailable on this device"
            return
        }
        if (!g.canAuthenticate()) {
            biometricError = if (allowWeak) {
                "No fingerprint or face is enrolled on this device"
            } else {
                "No strong biometric is enrolled. Enable 'Allow face unlock' " +
                    "below if your device only offers face scanning."
            }
            return
        }
        val key = keyProvider()
        if (key == null) {
            biometricError = "Your vault must be unlocked first"
            return
        }

        biometricBusy = true
        biometricError = null

        g.enroll(key, object : BiometricGate.Callback {
            override fun onUnlocked(unwrapped: ByteArray) {
                try {
                    biometricEnabled = true
                    biometricBusy = false
                } finally {
                    key.fill(0)
                }
            }

            override fun onFailed(message: String) {
                try {
                    biometricBusy = false
                    biometricError = message
                } finally {
                    key.fill(0)
                }
            }

            override fun onCancelled() {
                try {
                    biometricBusy = false
                } finally {
                    key.fill(0)
                }
            }
        })
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // ---- Biometrics ---------------------------------------------------
        SectionCard(
            icon = Icons.Filled.Fingerprint,
            title = stringResource(R.string.settings_biometrics),
        ) {
            ToggleRow(
                label = stringResource(R.string.settings_biometric_unlock),
                checked = biometricEnabled,
                enabled = !biometricBusy,
                onCheckedChange = { want ->
                    if (want) {
                        enableBiometrics(encryptionKeyForBiometricEnrolment)
                    } else {
                        gate()?.clear()
                        biometricEnabled = false
                        biometricError = null
                    }
                },
            )

            if (biometricBusy) {
                Text(
                    text = stringResource(R.string.settings_biometric_confirm),
                    style = MaterialTheme.typography.bodySmall,
                    color = Gold,
                )
            }

            Text(
                text = stringResource(R.string.settings_biometric_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            biometricError?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = BadRed,
                )
            }

            Spacer(Modifier.height(4.dp))

            // State for confirmation dialog
            var showWeakConfirm by remember { mutableStateOf(false) }
            var pendingWeakValue by remember { mutableStateOf(false) }

            // Hoisted out of the callback: `stringResource` is composable and
            // `onCheckedChange` is an ordinary lambda, so calling it there
            // does not compile.
            val weakReenrolNote = stringResource(R.string.settings_weak_reenrol)
            val weakConfirmTitle = stringResource(R.string.settings_weak_confirm_title)
            val weakConfirmMessage = stringResource(R.string.settings_weak_confirm_message)
            val weakConfirmOk = stringResource(R.string.settings_weak_confirm_ok)
            val weakConfirmCancel = stringResource(R.string.settings_weak_confirm_cancel)

            ToggleRow(
                label = stringResource(R.string.settings_allow_weak),
                checked = allowWeak,
                enabled = !biometricBusy,
                onCheckedChange = { want ->
                    if (biometricEnabled && want != allowWeak) {
                        // Show confirmation dialog when toggling while biometric unlock is active
                        pendingWeakValue = want
                        showWeakConfirm = true
                    } else {
                        allowWeak = want
                        app.settings.allowWeakBiometrics = want
                    }
                },
            )

            if (showWeakConfirm) {
                AlertDialog(
                    onDismissRequest = { showWeakConfirm = false },
                    title = { Text(weakConfirmTitle) },
                    text = { Text(weakConfirmMessage) },
                    confirmButton = {
                        androidx.compose.material3.TextButton(
                            onClick = {
                                allowWeak = pendingWeakValue
                                app.settings.allowWeakBiometrics = pendingWeakValue
                                if (biometricEnabled) {
                                    gate()?.clear()
                                    biometricEnabled = false
                                    biometricError = weakReenrolNote
                                }
                                showWeakConfirm = false
                            },
                        ) {
                            Text(weakConfirmOk)
                        }
                    },
                    dismissButton = {
                        androidx.compose.material3.TextButton(
                            onClick = { showWeakConfirm = false },
                        ) {
                            Text(weakConfirmCancel)
                        }
                    },
                )
            }

            Text(
                text = stringResource(R.string.settings_allow_weak_body),
                style = MaterialTheme.typography.bodySmall,
                color = WarnAmber,
            )
        }

        // ---- Autofill -----------------------------------------------------
        SectionCard(
            icon = Icons.AutoMirrored.Filled.Login,
            title = stringResource(R.string.settings_autofill),
        ) {
            StatusRow(
                label = stringResource(R.string.settings_autofill_status),
                value = if (autofillEnabled) {
                    stringResource(R.string.autofill_enabled)
                } else {
                    stringResource(R.string.autofill_disabled)
                },
                color = if (autofillEnabled) GoodGreen else WarnAmber,
            )

            Text(
                text = stringResource(R.string.autofill_service_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedButton(
                onClick = { openAutofillSettings(context) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (autofillEnabled) {
                        stringResource(R.string.settings_autofill_change)
                    } else {
                        stringResource(R.string.autofill_open_settings)
                    },
                )
            }
        }

        // ---- Clipboard ----------------------------------------------------
        SectionCard(
            icon = Icons.Filled.ContentPaste,
            title = stringResource(R.string.settings_clipboard),
        ) {
            Text(
                text = stringResource(R.string.settings_clipboard_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            ClipboardOptions(
                selected = clipboardSeconds,
                onSelect = { seconds ->
                    clipboardSeconds = seconds
                    app.settings.clipboardClearSeconds = seconds
                },
            )
        }

        // ---- Session ------------------------------------------------------
        SectionCard(
            icon = Icons.Filled.Visibility,
            title = stringResource(R.string.settings_session),
        ) {
            Text(
                text = stringResource(R.string.settings_session_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedButton(
                onClick = onLockVault,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.settings_lock_now))
            }
        }

        // ---- Active sessions ------------------------------------------------
        SectionCard(
            icon = Icons.Filled.Devices,
            title = stringResource(R.string.settings_active_sessions),
        ) {
            Text(
                text = stringResource(R.string.settings_active_sessions_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when {
                sessionsBusy && sessions == null -> Text(
                    text = stringResource(R.string.settings_sessions_loading),
                    style = MaterialTheme.typography.bodySmall,
                    color = Gold,
                )

                sessionsError != null -> Text(
                    text = sessionsError ?: "",
                    style = MaterialTheme.typography.bodySmall,
                    color = BadRed,
                )

                sessions != null && sessions!!.isEmpty() -> Text(
                    text = stringResource(R.string.settings_sessions_empty),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                else -> sessions?.forEach { session ->
                    val device = session.device
                        ?: stringResource(R.string.settings_sessions_unknown_device)
                    val marker = if (session.current) {
                        " · " + stringResource(R.string.settings_sessions_current)
                    } else {
                        ""
                    }
                    Text(
                        text = device + marker + "\n" + shortInstant(session.lastSeen),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (session.current) {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        } else {
                            MaterialTheme.colorScheme.onSurface
                        },
                    )
                }
            }

            sessionsNotice?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = GoodGreen,
                )
            }

            OutlinedButton(
                onClick = {
                    sessionsNotice = null
                    scope.launch {
                        sessionsBusy = true
                        sessionsError = null
                        app.repository.revokeOtherSessions()
                            .onSuccess { revoked ->
                                sessionsNotice = if (revoked > 0) {
                                    signedOutN.format(revoked)
                                } else {
                                    signedOutNone
                                }
                                loadSessions()
                            }
                            .onFailure { sessionsError = apiMessage(it) }
                        sessionsBusy = false
                    }
                },
                enabled = !sessionsBusy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (sessionsBusy) {
                        stringResource(R.string.settings_sign_out_others_busy)
                    } else {
                        stringResource(R.string.settings_sign_out_others)
                    },
                )
            }

            OutlinedButton(
                onClick = ::loadSessions,
                enabled = !sessionsBusy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.settings_reload))
            }
        }

        // ---- Security activity ----------------------------------------------
        SectionCard(
            icon = Icons.Filled.History,
            title = stringResource(R.string.settings_security_activity),
        ) {
            Text(
                text = stringResource(R.string.settings_security_activity_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when {
                activityBusy && activity == null -> Text(
                    text = stringResource(R.string.settings_activity_loading),
                    style = MaterialTheme.typography.bodySmall,
                    color = Gold,
                )

                activityError != null -> Text(
                    text = activityError ?: "",
                    style = MaterialTheme.typography.bodySmall,
                    color = BadRed,
                )

                activity != null && activity!!.isEmpty() -> Text(
                    text = stringResource(R.string.settings_activity_empty),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                else -> activity?.forEach { event ->
                    Text(
                        text = auditLabel(event.event) + "\n" +
                            shortInstant(event.at) + event.detail.orEmpty().let { d ->
                                if (d.isBlank()) "" else " · $d"
                            },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
            }

            OutlinedButton(
                onClick = ::loadActivity,
                enabled = !activityBusy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.settings_reload))
            }
        }

        // ---- Change master password -----------------------------------------
        SectionCard(
            icon = Icons.Filled.Password,
            title = stringResource(R.string.settings_change_password),
        ) {
            Text(
                text = stringResource(R.string.settings_change_password_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            passwordNotice?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = GoodGreen,
                )
            }

            OutlinedButton(
                onClick = {
                    passwordNotice = null
                    passwordError = null
                    currentPassword = ""
                    newPassword = ""
                    confirmPassword = ""
                    showPasswordDialog = true
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.settings_change_password))
            }
        }
    }

    if (showPasswordDialog) {
        AlertDialog(
            onDismissRequest = { if (!passwordBusy) showPasswordDialog = false },
            title = { Text(passwordTitle) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = currentPassword,
                        onValueChange = { currentPassword = it },
                        label = { Text(stringResource(R.string.settings_current_password)) },
                        singleLine = true,
                        enabled = !passwordBusy,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = newPassword,
                        onValueChange = { newPassword = it },
                        label = { Text(stringResource(R.string.settings_new_password)) },
                        singleLine = true,
                        enabled = !passwordBusy,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = confirmPassword,
                        onValueChange = { confirmPassword = it },
                        label = { Text(stringResource(R.string.settings_confirm_password)) },
                        singleLine = true,
                        enabled = !passwordBusy,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    passwordError?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = BadRed)
                    }
                    if (passwordBusy) {
                        Text(
                            stringResource(R.string.settings_password_change_busy),
                            style = MaterialTheme.typography.bodySmall,
                            color = Gold,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !passwordBusy,
                    onClick = {
                        if (newPassword != confirmPassword) {
                            passwordError = passwordMismatch
                            return@TextButton
                        }
                        // Refusing before the network call: pushing the EMPTY
                        // placeholder while the first pull is still in flight
                        // would replace the whole server blob with nothing.
                        if (!vaultLoadedGate()) {
                            showPasswordDialog = false
                            return@TextButton
                        }
                        val vault = app.repository.openVault
                        if (vault == null) {
                            passwordError = passwordFallbackError
                            return@TextButton
                        }
                        scope.launch {
                            passwordBusy = true
                            passwordError = null
                            app.repository.changeMasterPassword(
                                current = currentPassword.toCharArray(),
                                updated = newPassword.toCharArray(),
                                vault = vault,
                            )
                                .onSuccess {
                                    passwordBusy = false
                                    passwordNotice = passwordDone
                                    showPasswordDialog = false
                                }
                                .onFailure { throwable ->
                                    passwordBusy = false
                                    passwordError = throwable.message
                                        ?.takeIf { it.isNotBlank() }
                                        ?: passwordFallbackError
                                }
                        }
                    },
                ) {
                    Text(stringResource(R.string.settings_password_change_confirm))
                }
            },
            dismissButton = {
                TextButton(
                    enabled = !passwordBusy,
                    onClick = { showPasswordDialog = false },
                ) {
                    Text(stringResource(R.string.settings_cancel))
                }
            },
        )
    }
}
}

@Composable
private fun SectionCard(
    icon: ImageVector,
    title: String,
    // The receiver is the *scope* type, not the `Column` function itself —
    // `Column.() -> Unit` would take the composable as the receiver and make
    // every call inside it non-composable.
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(16.dp))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp))
            .padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(10.dp))
            Text(text = title, style = MaterialTheme.typography.titleMedium)
        }
        Spacer(Modifier.height(12.dp))
        content()
    }
}

@Composable
private fun ToggleRow(
    label: String,
    checked: Boolean,
    enabled: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
        )
        Switch(checked = checked, enabled = enabled, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun StatusRow(label: String, value: String, color: androidx.compose.ui.graphics.Color) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
        )
        Text(text = value, style = MaterialTheme.typography.bodyMedium, color = color)
    }
}

@Composable
private fun ClipboardOptions(selected: Int, onSelect: (Int) -> Unit) {
    val options = listOf(20, 30, 60, 0)
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        options.forEach { seconds ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onSelect(seconds) }
                    .padding(vertical = 6.dp),
            ) {
                RadioButton(selected = selected == seconds, onClick = { onSelect(seconds) })
                Spacer(Modifier.width(4.dp))
        Text(
            text = if (selected == seconds) {
                stringResource(R.string.settings_clipboard_never)
            } else {
                stringResource(R.string.settings_clipboard_seconds, seconds)
            },
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = if (selected == seconds) FontWeight.SemiBold else FontWeight.Normal,
        )
            }
        }
    }
}

/** Server messages are phrased for users; raw IO failures are not. */
private fun apiMessage(throwable: Throwable): String =
    throwable.message?.takeIf { it.isNotBlank() }
        ?: "Something went wrong. Check your connection and try again."

/** `2026-10-15T17:34:31.099160+00:00` → `2026-10-15 17:34 UTC`. */
private fun shortInstant(iso: String): String =
    if (iso.length >= 16) iso.take(16).replace('T', ' ') + " UTC" else iso

/** Audit event codes → text a user can act on; raw code as the fallback. */
private fun auditLabel(event: String): String = when (event) {
    "account_created" -> "Account created"
    "login_ok" -> "Signed in"
    "login_fail" -> "Failed sign-in"
    "session_revoked" -> "Signed out"
    "sessions_revoked" -> "Other sessions signed out"
    "blob_write" -> "Vault synced"
    "kdf_change" -> "Key derivation upgraded"
    "kdf_change_denied" -> "Key upgrade blocked"
    "password_changed" -> "Master password changed"
    "password_change_denied" -> "Password change attempt blocked"
    "rate_limited" -> "Too many attempts"
    else -> event
}
