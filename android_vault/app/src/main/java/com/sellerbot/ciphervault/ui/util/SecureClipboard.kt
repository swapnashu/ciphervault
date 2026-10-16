package com.sellerbot.ciphervault.ui.util

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copy with automatic clearing.
 *
 * Most password managers copy and forget, which leaves a credential sitting
 * in the clipboard for any app to read until the next copy overwrites it.
 * Android also mirrors the clipboard to Google's suggestion strip on many
 * builds, so "cleared" needs to happen promptly.
 *
 * We set a clear timestamp first and check it when the timer fires, so a
 * *second* copy does not get wiped early by the first one's timer.
 */
object SecureClipboard {

    /**
     * Default lifetime of a copied secret.
     *
     * Mutable rather than `const` so Settings can change it: the value is
     * read once at startup, because a mid-copy change would leave the
     * pending wipe armed for the old duration anyway.
     */
    var CLEAR_AFTER_MS: Long = 20_000L

    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null

    /**
     * `ClipDescription.EXTRA_IS_SENSITIVE` (API 33), spelled out as a literal.
     *
     * The constant itself arrived with API 33, but the description's extras
     * bag has existed since API 24, so the key can be set on every supported
     * build: newer systems stop mirroring the clip into the suggestion strip
     * and mark it as sensitive in clipboard history, and anything older just
     * ignores a key it does not know.
     */
    private const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

    /**
     * @param onCleared invoked on the main thread after the clipboard is
     *        wiped, so the UI can show "Clipboard cleared".
     */
    fun copy(
        context: Context,
        label: String,
        value: String,
        clearAfterMs: Long = CLEAR_AFTER_MS,
        onCleared: (() -> Unit)? = null,
    ) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        // The label appears in the system clipboard UI. Do not put the value
        // in the label - it would be rendered in the Android shell.
        val clip = ClipData.newPlainText(label, value)
        // Beyond the auto-clear below, tell the system this is a secret:
        // without it Android mirrors the value into the suggestion strip and
        // keeps it in clipboard history, where the timer never reaches.
        clip.description.extras = PersistableBundle().apply {
            putBoolean(EXTRA_IS_SENSITIVE, true)
        }
        clipboard.setPrimaryClip(clip)

        // Cancel any earlier wipe so this value gets its full window.
        pendingClear?.let(handler::removeCallbacks)
        pendingClear = null

        val clear = Runnable {
            // Only wipe if nothing new was copied in the meantime.
            val current = clipboard.primaryClip
            val ours = current?.getItemAt(0)?.coerceToText(context)?.toString()
            if (ours == null || ours == value) {
                clipboard.clearClip()
                onCleared?.invoke()
            }
            pendingClear = null
        }
        pendingClear = clear
        handler.postDelayed(clear, clearAfterMs)
    }

    /** Wipe immediately - called when the app leaves the foreground. */
    fun clearNow(context: Context) {
        pendingClear?.let(handler::removeCallbacks)
        pendingClear = null
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.clearClip()
    }

    /**
     * `clearPrimaryClip()` is API 28, but the app's minSdk is 26.
     *
     * On Android 8.0/8.1 there is no way to remove a clip outright, so we
     * overwrite it with an empty one. That still stops the credential being
     * offered back to other apps via the suggestion strip, which is the
     * exposure this class exists to close.
     */
    private fun ClipboardManager.clearClip() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clearPrimaryClip()
        } else {
            setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}
