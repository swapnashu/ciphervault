package com.sellerbot.ciphervault.ui.authenticator

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.crypto.Base32
import com.sellerbot.ciphervault.crypto.Totp
import com.sellerbot.ciphervault.model.Vault
import com.sellerbot.ciphervault.model.VaultEntry
import com.sellerbot.ciphervault.ui.util.SecureClipboard
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Every stored 2FA seed in one place, live.
 *
 * This is the screen the previous build was missing: codes existed only
 * inside a single entry's detail view, which meant the app could not be
 * used as an authenticator at all — you had to open each entry in turn to
 * read a code, and each open lost the countdown context.
 *
 * One ticker drives the whole list rather than one per row. Per-row
 * coroutines all fire on the same second boundary and would recompose the
 * list several times a second for no benefit.
 */
@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun AuthenticatorScreen(
    vault: Vault,
    onAddEntry: () -> Unit,
    onScanQr: () -> Unit,
    onOpenMenu: () -> Unit,
) {
    val context = LocalContext.current
    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    // One clock for every row.
    var nowSeconds by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(Unit) {
        while (true) {
            nowSeconds = System.currentTimeMillis() / 1000
            delay(1000L - (System.currentTimeMillis() % 1000L))
        }
    }

    val rows = remember(vault.liveEntries) { vault.totpRows() }
    val recentCopies = remember { mutableStateMapOf<String, Long>() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.nav_authenticator)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                navigationIcon = {
                    IconButton(onClick = onOpenMenu) {
                        Icon(Icons.Filled.Menu, contentDescription = stringResource(R.string.nav_menu))
                    }
                },
                actions = {
                    IconButton(onClick = onScanQr) {
                        Icon(Icons.Filled.QrCodeScanner, contentDescription = stringResource(R.string.nav_scan))
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onAddEntry,
                containerColor = MaterialTheme.colorScheme.primary,
            ) {
                Icon(Icons.Filled.Add, contentDescription = "Add entry")
            }
        },
    ) { padding ->
        if (rows.isEmpty()) {
            EmptyAuthenticator(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                onAddEntry = onAddEntry,
                onScanQr = onScanQr,
            )
            return@Scaffold
        }

        // Most recently used first: the account you just copied a code from
        // is the one you are about to need again.
        val ordered = remember(rows, recentCopies.size) {
            rows.sortedByDescending { recentCopies[it.entry.id] ?: it.entry.lastUsedAt ?: 0L }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(top = 4.dp, bottom = 2.dp),
                ) {
                    Text(
                        text = stringResource(R.string.authenticator_subtitle, ordered.size),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedButton(onClick = onScanQr) {
                        Icon(
                            Icons.Filled.QrCodeScanner,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.nav_scan))
                    }
                }
            }

            items(ordered, key = { it.entry.id }) { row ->
                TotpRow(
                    row = row,
                    nowSeconds = nowSeconds,
                    onClick = {
                        copyCode(context, row)
                        recentCopies[row.entry.id] = System.currentTimeMillis()
                        scope.launch {
                            snackbarHostState.showSnackbar(
                                context.getString(R.string.authenticator_copied, row.label),
                            )
                        }
                    },
                )
            }

            item { Spacer(Modifier.height(72.dp)) }
        }
    }
}

/** One entry's parsed seed, kept alongside the entry itself. */
private data class TotpRow(
    val entry: VaultEntry,
    val label: String,
    val secret: ByteArray,
    val digits: Int,
    val periodSeconds: Int,
    val algorithm: Totp.Algorithm,
)

private fun Vault.totpRows(): List<TotpRow> = liveEntries.mapNotNull { entry ->
    val raw = entry.totpSecret?.takeIf { it.isNotBlank() } ?: return@mapNotNull null
    // Base32.decode already tolerates padding, whitespace and lowercase, but
    // a secret pasted with stray punctuation is the common failure and is
    // cheaper to normalise here than to reject in the UI.
    val secret = runCatching {
        Base32.decode(raw.filter { !it.isWhitespace() && it != '=' })
    }.getOrNull()
    if (secret == null || secret.isEmpty()) return@mapNotNull null

    TotpRow(
        entry = entry,
        label = entry.title,
        secret = secret,
        // Defaults when the entry predates the parameter fields, so a seed
        // imported before they existed still produces the right code.
        digits = entry.totpDigits ?: Totp.DEFAULT_DIGITS,
        periodSeconds = entry.totpPeriodSeconds ?: Totp.DEFAULT_PERIOD_SECONDS,
        algorithm = Totp.Algorithm.fromUri(entry.totpAlgorithm),
    )
}

private fun copyCode(context: Context, row: TotpRow) {
    val code = runCatching {
        Totp.totp(
            secret = row.secret,
            atSeconds = System.currentTimeMillis() / 1000,
            digits = row.digits,
            periodSeconds = row.periodSeconds,
            algorithm = row.algorithm,
        )
    }.getOrNull() ?: return

    SecureClipboard.copy(
        context = context,
        label = context.getString(R.string.authenticator_clipboard_label),
        value = code,
        // Shorter than a password: the code is worthless in ~30 seconds and
        // leaving it around is a bigger risk than the convenience is worth.
        clearAfterMs = 20_000L,
    )
}

@Composable
private fun TotpRow(
    row: TotpRow,
    nowSeconds: Long,
    onClick: () -> Unit,
) {
    val remaining = Totp.secondsRemaining(nowSeconds, row.periodSeconds)
    val progress = remaining.toFloat() / row.periodSeconds

    // Expiring soon is worth flagging: the last few seconds are when people
    // paste a code the service has already rotated past.
    val urgent = remaining <= 5

    Card(
        onClick = onClick,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(
                1.dp,
                if (urgent) MaterialTheme.colorScheme.error.copy(alpha = 0.45f)
                else MaterialTheme.colorScheme.outlineVariant,
                RoundedCornerShape(14.dp),
            ),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .size(38.dp)
                    .background(
                        MaterialTheme.colorScheme.surfaceVariant,
                        RoundedCornerShape(10.dp),
                    ),
            ) {
                Icon(
                    imageVector = Icons.Filled.Key,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(18.dp),
                )
            }

            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = row.label,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )

                Spacer(Modifier.height(6.dp))

                LinearProgressIndicator(
                    progress = { progress },
                    color = if (urgent) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary,
                    trackColor = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(4.dp),
                )

                Spacer(Modifier.height(6.dp))

                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Timer,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(13.dp),
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        text = stringResource(R.string.authenticator_seconds, remaining),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (urgent) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Spacer(Modifier.width(12.dp))

            Text(
                text = groupCode(codeFor(row, nowSeconds)),
                style = MaterialTheme.typography.headlineSmall,
                fontFamily = FontFamily.Monospace,
                textAlign = TextAlign.End,
                color = MaterialTheme.colorScheme.onSurface,
            )

            Icon(
                imageVector = Icons.Filled.ContentCopy,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier
                    .padding(start = 10.dp)
                    .size(16.dp),
            )
        }
    }
}

private fun codeFor(row: TotpRow, nowSeconds: Long): String =
    runCatching {
        Totp.totp(row.secret, nowSeconds, row.digits, row.periodSeconds, row.algorithm)
    }.getOrDefault("------")

/** `123456` -> `123 456`. The gap is what makes a six-digit number readable. */
private fun groupCode(code: String): String =
    if (code.length == 6) "${code.take(3)} ${code.drop(3)}" else code

@Composable
private fun EmptyAuthenticator(
    modifier: Modifier = Modifier,
    onAddEntry: () -> Unit,
    onScanQr: () -> Unit,
) {
    Column(
        modifier = modifier.padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Filled.Key,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(48.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(R.string.authenticator_empty_title),
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.authenticator_empty_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(24.dp))
        OutlinedButton(onClick = onScanQr) {
            Icon(Icons.Filled.QrCodeScanner, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.authenticator_scan_cta))
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onAddEntry) {
            Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.authenticator_empty_cta))
        }
    }
}
