package com.sellerbot.ciphervault.ui.vault

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.StickyNote2
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CreditCard
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.model.EntryType
import com.sellerbot.ciphervault.model.Vault
import com.sellerbot.ciphervault.model.VaultEntry
import com.sellerbot.ciphervault.ui.theme.Gold
import com.sellerbot.ciphervault.ui.theme.GoodGreen

/**
 * One section of the vault: a searchable list of entries, filtered by the
 * drawer's selected type.
 *
 * The biometric and autofill dialogs that used to live here have moved to
 * the Settings section. They were reachable only from two unlabelled icons
 * in the top bar, which made them effectively undiscoverable.
 */
@androidx.compose.material3.ExperimentalMaterial3Api
@Composable
fun VaultListScreen(
    vault: Vault,
    filter: VaultFilter,
    syncing: Boolean,
    loaded: Boolean,
    error: String?,
    onRetryError: () -> Unit,
    onOpenMenu: () -> Unit,
    onLockVault: () -> Unit,
    onOpenEntry: (String) -> Unit,
) {
    var query by remember { mutableStateOf("") }

    // Search the vault, then filter: filtering first would mean a search
    // only ever looked inside one type, which is not what the box says.
    val searched = remember(vault, query) { vault.search(query) }
    val entries = remember(searched, filter) { filter.select(searched) }
    val favorites = entries.filter { it.favorite }
    val rest = entries.filterNot { it.favorite }
    val showFavoriteHeader = filter != VaultFilter.FAVORITES
    // "Nothing in this section" and "nothing matched your search" are
    // different problems and need different messages.
    val sectionEmpty = remember(vault, filter) { filter.select(vault.liveEntries).isEmpty() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(filter.titleRes)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                navigationIcon = {
                    IconButton(onClick = onOpenMenu) {
                        Icon(Icons.Filled.Menu, contentDescription = stringResource(R.string.nav_menu))
                    }
                },
                actions = {
                    if (syncing) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .size(18.dp)
                                .padding(end = 4.dp),
                            strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                    IconButton(onClick = onLockVault) {
                        Icon(Icons.Filled.Lock, contentDescription = stringResource(R.string.nav_lock))
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { onOpenEntry("new") },
                containerColor = MaterialTheme.colorScheme.primary,
            ) {
                Icon(Icons.Filled.Add, contentDescription = "Add entry")
            }
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
        ) {
            // Sync failures live in VaultUiState.Unlocked.error and used to
            // have no renderer at all: a failed pull or push looked exactly
            // like an empty vault, and this is where the user would look.
            if (error != null) {
                ErrorBanner(message = error, onRetry = onRetryError)
                Spacer(Modifier.height(12.dp))
            }

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text(stringResource(R.string.vault_search)) },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth(),
            )

            Spacer(Modifier.height(12.dp))

            if (sectionEmpty) {
                EmptyState(loaded = loaded)
            } else if (entries.isEmpty()) {
                NoResults(query)
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (showFavoriteHeader && favorites.isNotEmpty()) {
                        item(key = "fav-header") {
                            SectionHeader(stringResource(R.string.vault_favorites))
                        }
                    }
                    items(favorites, key = { it.id }) { entry ->
                        EntryRow(entry) { onOpenEntry(entry.id) }
                    }

                    if (rest.isNotEmpty()) {
                        item(key = "all-header") {
                            SectionHeader(
                                if (showFavoriteHeader) stringResource(R.string.vault_all_items)
                                else stringResource(filter.titleRes),
                            )
                        }
                    }
                    items(rest, key = { it.id }) { entry ->
                        EntryRow(entry) { onOpenEntry(entry.id) }
                    }

                    item { Spacer(Modifier.height(72.dp)) }
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 4.dp, bottom = 4.dp),
    )
}

@Composable
private fun EntryRow(entry: VaultEntry, onClick: () -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            // White card on an off-white page is only a few levels apart, so
            // the row gets a hairline of its own rather than relying on shade.
            .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(12.dp))
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(12.dp),
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(40.dp)
                .background(MaterialTheme.colorScheme.surfaceVariant, CircleShape),
        ) {
            Icon(
                imageVector = entry.type.icon(),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp),
            )
        }

        Spacer(Modifier.width(12.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = entry.title,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val subtitle = entry.username ?: entry.url ?: entry.folder
            if (!subtitle.isNullOrBlank()) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        if (entry.favorite) {
            Icon(
                imageVector = Icons.Filled.Star,
                contentDescription = "Favorite",
                tint = Gold,
                modifier = Modifier.size(18.dp),
            )
        }

        if (entry.hasTotp()) {
            Icon(
                imageVector = Icons.Filled.Key,
                contentDescription = "Has 2FA",
                tint = GoodGreen,
                modifier = Modifier
                    .size(16.dp)
                    .padding(start = 6.dp),
            )
        }
    }
}

private fun EntryType.icon(): ImageVector = when (this) {
    EntryType.LOGIN -> Icons.Filled.LockOpen
    EntryType.NOTE -> Icons.AutoMirrored.Filled.StickyNote2
    EntryType.CARD -> Icons.Filled.CreditCard
    EntryType.IDENTITY, EntryType.TOTP -> Icons.Filled.Key
}

@Composable
private fun ErrorBanner(message: String, onRetry: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier
                    .weight(1f)
                    .padding(start = 12.dp, top = 4.dp, bottom = 4.dp),
            )
            TextButton(onClick = onRetry) {
                Text(stringResource(R.string.vault_error_retry))
            }
        }
    }
}

@Composable
private fun EmptyState(loaded: Boolean = true) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(bottom = 48.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(
            imageVector = Icons.Filled.Lock,
            contentDescription = null,
            tint = Gold,
            modifier = Modifier.size(48.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text(
            text = stringResource(
                if (loaded) R.string.vault_empty_title else R.string.vault_unavailable_title,
            ),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = stringResource(
                if (loaded) R.string.vault_empty_body else R.string.vault_unavailable_body,
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun NoResults(query: String) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(bottom = 48.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(R.string.vault_no_results, query),
            style = MaterialTheme.typography.titleMedium,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.vault_search_hint),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
