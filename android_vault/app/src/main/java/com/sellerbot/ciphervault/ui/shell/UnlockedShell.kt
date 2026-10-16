package com.sellerbot.ciphervault.ui.shell

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.ui.VaultUiState
import com.sellerbot.ciphervault.ui.VaultViewModel
import com.sellerbot.ciphervault.ui.authenticator.AuthenticatorScreen
import com.sellerbot.ciphervault.ui.security.SecurityScreen
import com.sellerbot.ciphervault.ui.settings.SettingsScreen
import com.sellerbot.ciphervault.ui.theme.Gold
import com.sellerbot.ciphervault.ui.vault.VaultFilter
import com.sellerbot.ciphervault.ui.vault.VaultListScreen
import kotlinx.coroutines.launch

/**
 * Top-level destinations inside an unlocked vault.
 *
 * Kept as an enum rather than navigation routes on purpose: these are all
 * the same session, none of them has arguments, and pushing them onto the
 * back stack would let the back button walk from Settings back into a
 * vault list that has already been filtered away.
 */
enum class VaultSection { VAULT, AUTHENTICATOR, SECURITY, SETTINGS }

/**
 * Everything the unlocked vault contains, behind one navigation drawer.
 *
 * The drawer is the only place that decides what the body shows, so the
 * four sections share a single sheet and a single back behaviour. It also
 * gives the app somewhere to put the things that had no home before —
 * scanning a QR code, the security audit, and the settings that were
 * previously buried behind two unlabelled top-bar icons.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UnlockedShell(
    viewModel: VaultViewModel,
    accountEmail: String?,
    biometricEnrolled: Boolean,
    onOpenEntry: (String) -> Unit,
    onScanQr: () -> Unit,
) {
    val state by viewModel.state.collectAsState()
    val unlocked = state as? VaultUiState.Unlocked ?: return

    val drawerState = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    var section by rememberSaveable { mutableStateOf(VaultSection.VAULT) }
    var filter by rememberSaveable { mutableStateOf(VaultFilter.ALL) }

    fun openMenu() {
        scope.launch { drawerState.open() }
    }

    fun goTo(target: VaultSection) {
        section = target
        scope.launch { drawerState.close() }
    }

    fun openEntry(id: String) {
        // Opening the add form on a vault that never finished loading would
        // let the user type into a shell whose save is refused; fail here
        // instead so the refusal lands on the banner where it can be read.
        if (id == "new" && !viewModel.refuseUnlessLoaded()) return
        onOpenEntry(id)
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            VaultDrawer(
                section = section,
                filter = filter,
                email = accountEmail,
                onSelectSection = ::goTo,
                onSelectFilter = { selected ->
                    filter = selected
                    goTo(VaultSection.VAULT)
                },
                onScanQr = {
                    scope.launch { drawerState.close() }
                    onScanQr()
                },
                onLock = {
                    scope.launch { drawerState.close() }
                    viewModel.lock()
                },
            )
        },
    ) {
        when (section) {
            VaultSection.VAULT -> VaultListScreen(
                vault = unlocked.vault,
                filter = filter,
                syncing = unlocked.syncing,
                loaded = unlocked.loaded,
                error = unlocked.error,
                onRetryError = viewModel::clearError,
                onOpenMenu = ::openMenu,
                onLockVault = { viewModel.lock() },
                onOpenEntry = { openEntry(it) },
            )

            VaultSection.AUTHENTICATOR -> AuthenticatorScreen(
                vault = unlocked.vault,
                onAddEntry = { openEntry("new") },
                onScanQr = onScanQr,
                onOpenMenu = ::openMenu,
            )

            VaultSection.SECURITY -> SecurityScreen(
                vault = unlocked.vault,
                onOpenEntry = onOpenEntry,
                onOpenMenu = ::openMenu,
            )

            VaultSection.SETTINGS -> SettingsScreen(
                encryptionKeyForBiometricEnrolment = viewModel::encryptionKeyForBiometricEnrolment,
                biometricEnrolled = biometricEnrolled,
                vaultLoadedGate = viewModel::refuseUnlessLoaded,
                onLockVault = { viewModel.lock() },
                onOpenMenu = ::openMenu,
            )
        }
    }
}

@Composable
private fun VaultDrawer(
    section: VaultSection,
    filter: VaultFilter,
    email: String?,
    onSelectSection: (VaultSection) -> Unit,
    onSelectFilter: (VaultFilter) -> Unit,
    onScanQr: () -> Unit,
    onLock: () -> Unit,
) {
    ModalDrawerSheet(
        drawerContainerColor = MaterialTheme.colorScheme.surface,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 16.dp),
        ) {
            DrawerHeader(email)

            Text(
                text = stringResource(R.string.nav_vault),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 28.dp, top = 8.dp, bottom = 4.dp),
            )

            VaultFilter.entries.forEach { item ->
                NavigationDrawerItem(
                    label = { Text(stringResource(item.titleRes)) },
                    icon = { Icon(item.icon, contentDescription = null) },
                    selected = section == VaultSection.VAULT && filter == item,
                    onClick = { onSelectFilter(item) },
                    modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
                )
            }

            HorizontalDivider(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                color = MaterialTheme.colorScheme.outlineVariant,
            )

            NavigationDrawerItem(
                label = { Text(stringResource(R.string.nav_authenticator)) },
                icon = { Icon(Icons.Filled.VerifiedUser, contentDescription = null) },
                selected = section == VaultSection.AUTHENTICATOR,
                onClick = { onSelectSection(VaultSection.AUTHENTICATOR) },
                modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
            )

            NavigationDrawerItem(
                label = { Text(stringResource(R.string.nav_scan)) },
                icon = { Icon(Icons.Filled.QrCodeScanner, contentDescription = null) },
                selected = false,
                onClick = onScanQr,
                modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
            )

            NavigationDrawerItem(
                label = { Text(stringResource(R.string.nav_security)) },
                icon = { Icon(Icons.Filled.Security, contentDescription = null) },
                selected = section == VaultSection.SECURITY,
                onClick = { onSelectSection(VaultSection.SECURITY) },
                modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
            )

            NavigationDrawerItem(
                label = { Text(stringResource(R.string.nav_settings)) },
                icon = { Icon(Icons.Filled.Settings, contentDescription = null) },
                selected = section == VaultSection.SETTINGS,
                onClick = { onSelectSection(VaultSection.SETTINGS) },
                modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
            )

            HorizontalDivider(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp),
                color = MaterialTheme.colorScheme.outlineVariant,
            )

            NavigationDrawerItem(
                label = { Text(stringResource(R.string.nav_lock)) },
                icon = { Icon(Icons.Filled.Lock, contentDescription = null) },
                selected = false,
                onClick = onLock,
                modifier = Modifier.padding(NavigationDrawerItemDefaults.ItemPadding),
            )
        }
    }
}

@Composable
private fun DrawerHeader(email: String?) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 28.dp, end = 28.dp, top = 28.dp, bottom = 12.dp),
    ) {
        Icon(
            imageVector = Icons.Filled.Fingerprint,
            contentDescription = null,
            tint = Gold,
            modifier = Modifier.size(34.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.SemiBold,
            )
            if (!email.isNullOrBlank()) {
                Text(
                    text = email,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(2.dp))
            Text(
                text = stringResource(R.string.nav_zero_knowledge),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
