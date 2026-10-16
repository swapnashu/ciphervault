package com.sellerbot.ciphervault.ui.entry

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Star
import com.google.zxing.BarcodeFormat
import com.google.zxing.MultiFormatWriter
import com.google.zxing.common.BitMatrix
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sellerbot.ciphervault.crypto.Base32
import com.sellerbot.ciphervault.crypto.Kdf
import com.sellerbot.ciphervault.crypto.PasswordGenerator
import com.sellerbot.ciphervault.crypto.Totp
import com.sellerbot.ciphervault.model.VaultEntry
import com.sellerbot.ciphervault.ui.VaultUiState
import com.sellerbot.ciphervault.ui.VaultViewModel
import com.sellerbot.ciphervault.ui.theme.BadRed
import com.sellerbot.ciphervault.ui.theme.Gold
import com.sellerbot.ciphervault.ui.theme.GoodGreen
import com.sellerbot.ciphervault.ui.theme.WarnAmber
import com.sellerbot.ciphervault.ui.util.SecureClipboard
import kotlinx.coroutines.delay
import android.graphics.Bitmap
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap

/**
 * Create or edit one entry.
 *
 * `entryId == "new"` opens a blank form; anything else is loaded from the
 * in-memory vault. Edits are local until [onSave] pushes them, so a failed
 * sync never discards what the user just typed.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryDetailScreen(
    entryId: String,
    viewModel: VaultViewModel,
    onScanQr: () -> Unit,
    onDone: () -> Unit,
) {
    val state by viewModel.state.collectAsState()
    val unlocked = state as? VaultUiState.Unlocked ?: return
    val context = LocalContext.current

    val existing = if (entryId == "new") null else unlocked.vault.entryById(entryId)

    // A missing entry means it was deleted on another device while this
    // screen was open. Back out rather than offering to save a ghost.
    LaunchedEffect(entryId, unlocked.vault) {
        if (entryId != "new" && existing == null) onDone()
    }

    var title by remember(entryId) { mutableStateOf(existing?.title ?: "") }
    var username by remember(entryId) { mutableStateOf(existing?.username ?: "") }
    var password by remember(entryId) { mutableStateOf(existing?.password ?: "") }
    var url by remember(entryId) { mutableStateOf(existing?.url ?: "") }
    var totpSecret by remember(entryId) { mutableStateOf(existing?.totpSecret ?: "") }
    var totpAlgorithm by remember(entryId) {
        mutableStateOf(existing?.totpAlgorithm ?: Totp.Algorithm.SHA1.uriName)
    }
    var totpDigits by remember(entryId) {
        mutableStateOf(existing?.totpDigits ?: Totp.DEFAULT_DIGITS)
    }
    var totpPeriod by remember(entryId) {
        mutableStateOf(existing?.totpPeriodSeconds ?: Totp.DEFAULT_PERIOD_SECONDS)
    }
    var notes by remember(entryId) { mutableStateOf(existing?.notes ?: "") }
    var favorite by remember(entryId) { mutableStateOf(existing?.favorite ?: false) }

    var showPassword by remember { mutableStateOf(false) }
    var showDeleteConfirm by remember { mutableStateOf(false) }
    var clipboardNote by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(clipboardNote) {
        if (clipboardNote != null) {
            delay(2000)
            clipboardNote = null
        }
    }

    // Consume a pending `otpauth://` deep link — from the manifest intent, or
    // from a QR scan started either here or from the drawer.
    //
    // Keyed on the payload rather than the entry id: a scan returns to this
    // screen *after* it has already composed, so an id-keyed effect would
    // never re-run and the seed would be silently dropped. Single-shot via
    // `takePendingOtpauth`, so backing out cannot leave it armed for the
    // next entry the user opens.
    val pendingOtpauth by viewModel.pendingOtpauth.collectAsState()
    LaunchedEffect(pendingOtpauth) {
        val pending = pendingOtpauth ?: return@LaunchedEffect
        viewModel.takePendingOtpauth()
        if (title.isBlank()) {
            title = pending.suggestedTitle.ifBlank { "Authenticator key" }
        }
        totpSecret = pending.secret
        // Parameters come from the URI, not from the defaults: an enrolment
        // that specifies 8 digits or a 60-second period would otherwise
        // generate a plausible-looking wrong code.
        totpAlgorithm = pending.algorithm
        totpDigits = pending.digits
        totpPeriod = pending.periodSeconds
    }

    fun save() {
        val now = System.currentTimeMillis()
        val base = existing ?: VaultEntry(
            id = "local-${now}",
            title = "",
            createdAt = now,
            updatedAt = now,
        )
        viewModel.upsert(
            base.copy(
                title = title.ifBlank { "Untitled" },
                username = username.ifBlank { null },
                password = password.ifBlank { null },
                url = url.ifBlank { null },
                totpSecret = totpSecret.uppercase().replace(" ", "").ifBlank { null },
                totpAlgorithm = if (totpSecret.isBlank()) null else totpAlgorithm,
                totpDigits = if (totpSecret.isBlank()) null else totpDigits,
                totpPeriodSeconds = if (totpSecret.isBlank()) null else totpPeriod,
                notes = notes.ifBlank { null },
                favorite = favorite,
                updatedAt = now,
                // Per-entry revision is what the conflict merge compares first
                // (`Vault.mergeWith`). Leaving it untouched meant an edit and
                // an untouched copy always looked equal, and the decision fell
                // to wall-clock time — two devices with skewed clocks could
                // both keep their own version of an entry.
                revision = base.revision + 1,
                passwordUpdatedAt = if (password != (existing?.password ?: null)) now
                else existing?.passwordUpdatedAt,
            ),
        )
        onDone()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (existing == null) "New entry" else "Edit entry") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                navigationIcon = {
                    IconButton(onClick = onDone) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { favorite = !favorite }) {
                        Icon(
                            imageVector = if (favorite) Icons.Filled.Star
                            else Icons.Outlined.Star,
                            contentDescription = if (favorite) "Remove favorite" else "Add favorite",
                            tint = Gold,
                        )
                    }
                    if (existing != null) {
                        IconButton(onClick = { showDeleteConfirm = true }) {
                            Icon(
                                Icons.Filled.Delete,
                                contentDescription = "Delete",
                                tint = BadRed,
                            )
                        }
                    }
                    IconButton(
                        onClick = { save() },
                        enabled = title.isNotBlank(),
                    ) {
                        Icon(Icons.Filled.Save, contentDescription = "Save")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Field("Title", title, { title = it }, required = true)

            Field("Username", username, { username = it }, keyboardType = KeyboardType.Email)

            SecretField(
                label = "Password",
                value = password,
                onValueChange = { password = it },
                revealed = showPassword,
                onToggleReveal = { showPassword = !showPassword },
                onCopy = {
                    SecureClipboard.copy(context, "password", password) {
                        clipboardNote = "Clipboard cleared"
                    }
                    clipboardNote = "Copied"
                },
                onGenerate = {
                    // Reveal it: silently swapping a hidden field the user
                    // cannot see would be worse than not generating at all.
                    password = PasswordGenerator.generate()
                    showPassword = true
                },
            )

            Field("URL", url, { url = it }, keyboardType = KeyboardType.Uri)

            HorizontalDivider()

            TotpSection(
                secret = totpSecret,
                algorithm = Totp.Algorithm.fromUri(totpAlgorithm),
                digits = totpDigits,
                periodSeconds = totpPeriod,
                onSecretChange = { totpSecret = it },
                onScanQr = onScanQr,
                onClipboard = { clipboardNote = it },
                entryTitle = title,
                entryAccount = username,
            )

            HorizontalDivider()

            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it },
                label = { Text("Notes") },
                minLines = 3,
                modifier = Modifier.fillMaxWidth(),
            )

            clipboardNote?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.labelMedium,
                    color = if (it == "Clipboard cleared") WarnAmber else GoodGreen,
                )
            }

            Spacer(Modifier.height(24.dp))
        }
    }

    if (showDeleteConfirm) {
        AlertDialog(
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("Delete this entry?") },
            text = {
                Text("\u201C${title.ifBlank { "Untitled" }}\u201D will be removed from your vault and synced to your other devices. This cannot be undone.")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showDeleteConfirm = false
                        existing?.let { viewModel.delete(it.id) }
                        onDone()
                    },
                ) {
                    Text("Delete", color = BadRed)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) {
                    Text("Cancel")
                }
            },
        )
    }
}

@Composable
private fun TotpSection(
    secret: String,
    algorithm: Totp.Algorithm,
    digits: Int,
    periodSeconds: Int,
    onSecretChange: (String) -> Unit,
    onScanQr: () -> Unit,
    onClipboard: (String) -> Unit,
    entryTitle: String = "",
    entryAccount: String = "",
) {
    val context = LocalContext.current
    var nowSeconds by remember { mutableStateOf(System.currentTimeMillis() / 1000) }
    var showShareQr by remember { mutableStateOf(false) }

    LaunchedEffect(secret) {
        while (true) {
            nowSeconds = System.currentTimeMillis() / 1000
            delay(1000)
        }
    }

    val decoded = remember(secret) {
        runCatching { Base32.decode(secret.uppercase().replace(" ", "")) }.getOrNull()
    }

    if (decoded != null && decoded.isNotEmpty()) {
        val code = remember(decoded, nowSeconds, algorithm, digits, periodSeconds) {
            runCatching { Totp.totp(decoded, nowSeconds, digits, periodSeconds, algorithm) }
                .getOrNull()
        }
        val remaining = remember(nowSeconds, periodSeconds) {
            Totp.secondsRemaining(nowSeconds, periodSeconds)
        }

        Column {
            Text(
                text = "Verification code",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(6.dp))
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = code.orEmpty().chunked(3).joinToString("  "),
                    style = MaterialTheme.typography.displayLarge,
                    color = when {
                        remaining <= 5 -> BadRed
                        remaining <= 10 -> WarnAmber
                        else -> GoodGreen
                    },
                    modifier = Modifier.weight(1f),
                )
                IconButton(
                    onClick = {
                        code?.let { value ->
                            SecureClipboard.copy(context, "verification code", value) {
                                onClipboard("Clipboard cleared")
                            }
                            onClipboard("Copied")
                        }
                    },
                    enabled = !code.isNullOrBlank(),
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy code")
                }
            }

            LinearProgressIndicator(
                progress = { remaining / periodSeconds.toFloat() },
                color = when {
                    remaining <= 5 -> BadRed
                    remaining <= 10 -> WarnAmber
                    else -> GoodGreen
                },
                trackColor = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = "Refreshes in ${remaining}s",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    OutlinedTextField(
        value = secret,
        onValueChange = onSecretChange,
        label = { Text("2FA secret (Base32)") },
        singleLine = true,
        supportingText = {
            Text("Paste a Base32 secret, or scan the site's QR code below.")
        },
        modifier = Modifier.fillMaxWidth(),
    )

    Spacer(Modifier.height(8.dp))

    // Share via QR code button
    if (decoded != null && decoded.isNotEmpty()) {
        OutlinedButton(
            onClick = { showShareQr = true },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Filled.QrCode, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text("Share via QR code")
        }
    }

    if (showShareQr && decoded != null && decoded.isNotEmpty()) {
        val shareUri = remember(decoded, algorithm, digits, periodSeconds, entryTitle, entryAccount) {
            // The Key URI is `otpauth://totp/Issuer:account`: the issuer is the
            // site (the entry title) and the account is the username. Passing
            // these the other way round produces `totp/<username>:<title>`,
            // which imports as an entry for the wrong service. With no
            // username the title doubles as the label and no issuer is
            // emitted, because "GitHub:GitHub" tells the receiving app nothing.
            val service = entryTitle.trim()
            val account = entryAccount.trim()
            com.sellerbot.ciphervault.crypto.TotpEntry(
                secret = decoded,
                label = account.ifBlank { service.ifBlank { "CipherVault entry" } },
                issuer = if (account.isBlank()) null else service.ifBlank { null },
                algorithm = algorithm,
                digits = digits,
                periodSeconds = periodSeconds,
            ).toUri()
        }
        QrShareDialog(
            uri = shareUri,
            title = entryTitle.ifBlank { "CipherVault entry" },
            onDismiss = { showShareQr = false },
        )
    }

    Spacer(Modifier.height(8.dp))

    OutlinedButton(
        onClick = onScanQr,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Icon(Icons.Filled.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Text("Scan QR code")
    }
}

/**
 * Dialog that displays a QR code for sharing a TOTP entry via otpauth:// URI.
 * The receiving device can scan this QR code to import the 2FA entry.
 */
@Composable
private fun QrShareDialog(
    uri: String,
    title: String,
    onDismiss: () -> Unit,
) {
    val imageBitmap = remember(uri) {
        val writer = MultiFormatWriter()
        val bitMatrix: BitMatrix = writer.encode(uri, BarcodeFormat.QR_CODE, 300, 300)
        val width = bitMatrix.width
        val height = bitMatrix.height
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                pixels[y * width + x] =
                    if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
            }
        }
        val androidBitmap = Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888)
        androidBitmap.asImageBitmap()
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Share via QR code") },
        text = {
            Column(Modifier.padding(16.dp)) {
                Text("Scan this QR code with another device to import the 2FA entry.")
                Spacer(Modifier.height(16.dp))
                androidx.compose.foundation.Image(
                    bitmap = imageBitmap,
                    contentDescription = "QR code for $title",
                    modifier = Modifier.size(256.dp),
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    text = "URI: $uri",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done") }
        },
    )
}

@Composable
private fun Field(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    required: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Text,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = {
            Text(if (required) "$label *" else label)
        },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun SecretField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    revealed: Boolean,
    onToggleReveal: () -> Unit,
    onCopy: () -> Unit,
    onGenerate: (() -> Unit)? = null,
) {
    Column {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            label = { Text(label) },
            singleLine = true,
            visualTransformation = if (revealed) VisualTransformation.None
            else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                Row {
                    if (onGenerate != null) {
                        IconButton(onClick = onGenerate) {
                            Icon(
                                imageVector = Icons.Filled.Refresh,
                                contentDescription = "Generate a new $label",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(20.dp),
                            )
                        }
                    }
                    IconButton(onClick = onToggleReveal) {
                        Text(
                            text = if (revealed) "HIDE" else "SHOW",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    IconButton(onClick = onCopy, enabled = value.isNotBlank()) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy $label")
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
        )

        // Only shown for a real secret, so an empty field does not advertise
        // "Very weak" before the user has typed anything.
        if (value.isNotBlank() && label == "Password") {
            val strength = remember(value) { Kdf.strength(value) }
            Text(
                text = strength.label,
                style = MaterialTheme.typography.labelMedium,
                color = when (strength) {
                    Kdf.Strength.EMPTY -> MaterialTheme.colorScheme.onSurfaceVariant
                    Kdf.Strength.VERY_WEAK, Kdf.Strength.WEAK -> BadRed
                    Kdf.Strength.FAIR -> WarnAmber
                    Kdf.Strength.STRONG, Kdf.Strength.VERY_STRONG -> GoodGreen
                },
            )
        }
    }
}
