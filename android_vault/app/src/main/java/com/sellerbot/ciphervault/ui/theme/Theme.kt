package com.sellerbot.ciphervault.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// ---- Surfaces: white on a whisper of warm grey -----------------------------
// The page is barely-off-white so that true white cards read as cards without
// needing a shadow. Warm greys rather than neutral ones keep the gold from
// going green next to them.
val Page = Color(0xFFF6F7F5)
val Surface = Color(0xFFFFFFFF)
val SurfaceHigh = Color(0xFFEFF2ED)
val OutlineDim = Color(0xFFDCE2DA)
val OutlineFaint = Color(0xFFE7EBE5)

// ---- Brand -----------------------------------------------------------------
val Emerald = Color(0xFF0B6B47)
val EmeraldSoft = Color(0xFFD9F2E6)
val EmeraldInk = Color(0xFF053F2B)

/**
 * Decorative gold: favourite stars, empty-state art, attention lines.
 *
 * 3.15:1 on white — fine for graphics and large text, too light to *read*
 * body copy with. [WarnAmber] is the text-safe gold for that.
 */
val Gold = Color(0xFFB08D1F)
val GoldSoft = Color(0xFFF7EFD9)
val GoldInk = Color(0xFF5A4411)

val TextPrimary = Color(0xFF10231B)
val TextMuted = Color(0xFF5C6B63)

val GoodGreen = Color(0xFF0F7A4F)
val WarnAmber = Color(0xFF8A6D1F)
val BadRed = Color(0xFFC0283F)

/** Countdown ring turns red as the TOTP code approaches expiry. */
fun totpRingColor(remainingSeconds: Int, periodSeconds: Int = 30): Color = when {
    remainingSeconds <= 5 -> BadRed
    remainingSeconds <= 10 -> WarnAmber
    else -> GoodGreen
}

private val VaultColors = lightColorScheme(
    primary = Emerald,
    onPrimary = Color.White,
    primaryContainer = EmeraldSoft,
    onPrimaryContainer = EmeraldInk,
    secondary = Gold,
    onSecondary = Color(0xFF1A1405),
    secondaryContainer = GoldSoft,
    onSecondaryContainer = GoldInk,
    background = Page,
    onBackground = TextPrimary,
    surface = Surface,
    onSurface = TextPrimary,
    surfaceVariant = SurfaceHigh,
    onSurfaceVariant = TextMuted,
    outline = OutlineDim,
    outlineVariant = OutlineFaint,
    error = BadRed,
    onError = Color.White,
)

/**
 * Monospace for TOTP codes so digits do not shift width as they change.
 */
val VaultTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 56.sp,
        letterSpacing = 6.sp,
    ),
    headlineSmall = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        letterSpacing = (-0.2).sp,
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        letterSpacing = (-0.1).sp,
    ),
    bodyMedium = TextStyle(
        fontSize = 15.sp,
        lineHeight = 21.sp,
    ),
    labelMedium = TextStyle(
        fontSize = 12.sp,
        letterSpacing = 0.4.sp,
    ),
)

/**
 * Fixed light palette.
 *
 * It does not follow the system dark setting: the white / emerald / gold
 * treatment *is* the product's identity, and a password manager that silently
 * inverts on a system toggle looks like it was swapped out from under you.
 * Screenshots remain blocked regardless - see the FLAG_SECURE in MainActivity.
 */
@Composable
fun CipherVaultTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = VaultColors,
        typography = VaultTypography,
        content = content,
    )
}
