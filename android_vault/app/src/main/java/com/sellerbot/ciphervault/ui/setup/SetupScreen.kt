package com.sellerbot.ciphervault.ui.setup

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import com.sellerbot.ciphervault.crypto.Kdf
import com.sellerbot.ciphervault.ui.VaultUiState
import com.sellerbot.ciphervault.ui.VaultViewModel
import com.sellerbot.ciphervault.ui.theme.BadRed
import com.sellerbot.ciphervault.ui.theme.GoodGreen
import com.sellerbot.ciphervault.ui.theme.WarnAmber

/**
 * First-run screen: either create an account or sign in to an existing one.
 *
 * The master password is the only thing that opens the vault — there is no
 * reset link, because the server cannot decrypt anything to reset it. That
 * has to be stated *before* the user commits, not discovered afterwards.
 */
@Composable
fun SetupScreen(viewModel: VaultViewModel) {
    val state by viewModel.state.collectAsState()

    var isRegistering by rememberSaveable { mutableStateOf(true) }
    var email by rememberSaveable { mutableStateOf("") }
    // Deliberately *not* rememberSaveable: those two survive in the saved
    // instance-state Bundle the framework persists for process death, which
    // makes the master password and its confirmation recoverable from a
    // parcel after the screen is gone. Rotating the device clears them —
    // the correct trade for a field that opens the vault.
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }

    val busy = (state as? VaultUiState.Setup)?.busy ?: false
    val error = (state as? VaultUiState.Setup)?.error

    // Local validation so the user gets feedback while typing rather than
    // only after a network round trip.
    val emailValid = email.contains("@") && email.trim().length > 3
    val strength = Kdf.strength(password)
    val confirmMatches = confirm == password
    val canSubmit = when {
        busy -> false
        !emailValid -> false
        password.length < 12 -> false
        isRegistering && !confirmMatches -> false
        else -> true
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "CipherVault",
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = "Your vault is encrypted before it ever leaves this phone.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Spacer(Modifier.height(28.dp))

        Text(
            text = if (isRegistering) "Create your vault" else "Sign in",
            style = MaterialTheme.typography.titleMedium,
        )

        Spacer(Modifier.height(16.dp))

        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("Email") },
            singleLine = true,
            enabled = !busy,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(12.dp))

        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Master password") },
            singleLine = true,
            enabled = !busy,
            visualTransformation = if (showPassword) VisualTransformation.None
            else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        imageVector = if (showPassword) Icons.Filled.VisibilityOff
                        else Icons.Filled.Visibility,
                        contentDescription = if (showPassword) "Hide password" else "Show password",
                    )
                }
            },
            modifier = Modifier.fillMaxWidth(),
        )

        if (isRegistering && password.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            PasswordStrength(strength)
        }

        if (isRegistering) {
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = confirm,
                onValueChange = { confirm = it },
                label = { Text("Confirm master password") },
                singleLine = true,
                enabled = !busy,
                isError = confirm.isNotEmpty() && !confirmMatches,
                supportingText = {
                    if (confirm.isNotEmpty() && !confirmMatches) {
                        Text("Passwords do not match", color = BadRed)
                    }
                },
                visualTransformation = if (showPassword) VisualTransformation.None
                else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Spacer(Modifier.height(12.dp))

        // Must be visible before they commit, not discovered afterwards.
        Text(
            text = "There is no password reset. The server cannot read your " +
                "vault, so nobody can unlock it for you. Write it down.",
            style = MaterialTheme.typography.labelMedium,
            color = WarnAmber,
        )

        error?.let {
            Spacer(Modifier.height(8.dp))
            Text(text = it, color = BadRed, style = MaterialTheme.typography.bodyMedium)
        }

        Spacer(Modifier.height(20.dp))

        Button(
            onClick = {
                val chars = password.toCharArray()
                if (isRegistering) {
                    viewModel.register(email.trim(), chars)
                } else {
                    viewModel.login(email.trim(), chars)
                }
                // The ViewModel has taken ownership of the array.
                password = ""
                confirm = ""
            },
            enabled = canSubmit,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp,
                )
            } else {
                Text(if (isRegistering) "Create vault" else "Sign in")
            }
        }

        Spacer(Modifier.height(8.dp))

        TextButton(
            onClick = {
                isRegistering = !isRegistering
                viewModel.clearError()
            },
            enabled = !busy,
        ) {
            Text(
                if (isRegistering) "Already have a vault? Sign in"
                else "New here? Create a vault",
            )
        }
    }
}

@Composable
private fun PasswordStrength(strength: Kdf.Strength) {
    Column(modifier = Modifier.fillMaxWidth()) {
        LinearProgressIndicator(
            progress = { strength.score / 5f },
            color = when {
                strength.score <= 1 -> BadRed
                strength.score <= 3 -> WarnAmber
                else -> GoodGreen
            },
            trackColor = MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = strength.label,
            style = MaterialTheme.typography.labelMedium,
            color = when {
                strength.score <= 1 -> BadRed
                strength.score <= 3 -> WarnAmber
                else -> GoodGreen
            },
        )
    }
}
