package com.sellerbot.ciphervault.ui.util

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager
import com.sellerbot.ciphervault.autofill.VaultAutofillService

/**
 * Whether *this* app is the chosen autofill provider.
 *
 * `AutofillManager.hasEnabledAutofillServices()` only tells us that somebody
 * is the provider, so with Bitwarden or Google Autofill selected it would
 * report green while CipherVault never gets a fill request. Naming the
 * provider directly is only possible from API 28; between 26 and 27 we fall
 * back to the weaker "a provider exists" answer, which is what the older
 * autofill API can offer.
 */
fun isCipherVaultAutofill(context: Context): Boolean {
    val manager = context.getSystemService(AutofillManager::class.java) ?: return false
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
        return manager.hasEnabledAutofillServices()
    }
    val selected = manager.autofillServiceComponentName ?: return false
    return selected == ComponentName(context, VaultAutofillService::class.java)
}

/**
 * Hand off to the system autofill picker.
 *
 * Enabling autofill is a system setting, not an app one, so all the app can
 * do is launch the screen and re-read on resume. Not every OEM ships the
 * dedicated picker; falling back to the settings root beats crashing.
 */
fun openAutofillSettings(context: Context) {
    val primary = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
    val fallback = Intent(Settings.ACTION_SETTINGS)
    runCatching { context.startActivity(primary) }
        .onFailure { runCatching { context.startActivity(fallback) } }
}
