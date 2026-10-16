package com.sellerbot.ciphervault.ui.lock

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.sellerbot.ciphervault.R
import com.sellerbot.ciphervault.VaultApp
import com.sellerbot.ciphervault.security.BiometricGate
import com.sellerbot.ciphervault.ui.VaultUiState
import com.sellerbot.ciphervault.ui.VaultViewModel
import com.sellerbot.ciphervault.ui.theme.BadRed
import com.sellerbot.ciphervault.ui.util.SecureClipboard

/**
 * Unlock screen for a registered device.
 *
 * Biometrics are offered when the Keystore holds a wrapped key *and* the
 * device can satisfy whatever strength that key was minted at. With the
 * default (strong-only) a Class 1/2 face unlock is not offered here — falling
 * back to it would quietly downgrade to an authenticator Android itself
 * considers insufficient. Users who opt in from Settings get the weaker
 * prompt instead.
 */
@Composable
fun LockScreen(viewModel: VaultViewModel) {
    val state by viewModel.state.collectAsState()
    val locked = state as? VaultUiState.Locked ?: return

    val context = LocalContext.current
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    val focusRequester = remember { FocusRequester() }

    // Offer biometrics only when there is actually something to unwrap.
    val app = context.applicationContext as VaultApp
    val biometricReady = locked.biometricAvailable &&
        app.keystore.keyExists() &&
        !app.credentials.wrappedVaultKeyBase64.isNullOrBlank()

    fun tryBiometric() {
        val activity = context as? FragmentActivity ?: return
        BiometricGate.authenticate(
            activity = activity,
            keystore = app.keystore,
            credentials = app.credentials,
            allowWeakBiometrics = app.settings.allowWeakBiometrics,
            onSuccess = { unwrappedKey ->
                viewModel.unlockWithEncryptionKey(unwrappedKey)
            },
            onFailure = {
                // Fall through to password entry rather than blocking.
                viewModel.clearError()
                focusRequester.requestFocus()
            },
        )
    }

    LaunchedEffect(biometricReady) {
        if (biometricReady) tryBiometric()
    }

    // Locking is the one moment the app can be sure nothing needs the
    // clipboard any more. Wiping it here covers the copy the user made just
    // before the auto-lock timer fired.
    LaunchedEffect(Unit) {
        SecureClipboard.clearNow(context)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "Vault locked",
            style = MaterialTheme.typography.headlineSmall,
        )
        Spacer(Modifier.height(6.dp))
        Text(
            text = locked.userEmailHint.orEmpty().ifEmpty { "Enter your master password" },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(28.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Master password") },
            singleLine = true,
            enabled = !locked.busy,
            isError = locked.error != null,
            visualTransformation = if (showPassword) VisualTransformation.None
            else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = androidx.compose.ui.text.input.ImeAction.Done,
            ),
            keyboardActions = KeyboardActions(
                onDone = {
                    if (password.isNotBlank()) {
                        viewModel.unlock(password.toCharArray())
                        password = ""
                    }
                },
            ),
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        imageVector = if (showPassword) Icons.Filled.VisibilityOff
                        else Icons.Filled.Visibility,
                        contentDescription = if (showPassword) "Hide password" else "Show password",
                    )
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(focusRequester),
        )

        locked.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(text = it, color = BadRed, style = MaterialTheme.typography.bodyMedium)
        }

        Spacer(Modifier.height(20.dp))

        Button(
            onClick = {
                if (password.isNotBlank()) {
                    viewModel.unlock(password.toCharArray())
                    password = ""
                }
            },
            enabled = !locked.busy && password.isNotBlank(),
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            if (locked.busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp,
                )
            } else {
                Text("Unlock")
            }
        }

        if (biometricReady) {
            Spacer(Modifier.height(12.dp))
            OutlinedButton(
                onClick = { tryBiometric() },
                enabled = !locked.busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
            ) {
                Icon(Icons.Filled.Fingerprint, contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text("Use biometrics")
            }
        } else {
            // The button is absent until a biometric has been enrolled, and
            // enrolment needs an unlocked vault — so without saying so here
            // the feature looks simply missing, which is exactly how it was
            // reported.
            Spacer(Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.lock_biometric_hint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
