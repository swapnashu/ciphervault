package com.sellerbot.ciphervault.ui

import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.sellerbot.ciphervault.BuildConfig
import com.sellerbot.ciphervault.VaultApp
import com.sellerbot.ciphervault.ui.entry.EntryDetailScreen
import com.sellerbot.ciphervault.ui.lock.LockScreen
import com.sellerbot.ciphervault.ui.scan.QrScannerScreen
import com.sellerbot.ciphervault.ui.setup.SetupScreen
import com.sellerbot.ciphervault.ui.shell.UnlockedShell
import com.sellerbot.ciphervault.ui.theme.CipherVaultTheme

/**
 * How long the app may sit in the background before the session is dropped
 * on the next resume. Two minutes: long enough that replying to a message
 * does not force a re-unlock, short enough that a forgotten open vault on a
 * desk does not stay decrypted all afternoon.
 */
private const val BACKGROUND_LOCK_AFTER_MS = 2 * 60 * 1000L

/**
 * Extends `FragmentActivity` rather than `ComponentActivity` because
 * `androidx.biometric.BiometricPrompt` only accepts a `FragmentActivity`.
 * `FragmentActivity` is a `ComponentActivity`, so `setContent` still applies.
 */
class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Explicitly light rather than the default auto-detect: the app is
        // white whatever the system is set to, and auto picks dark bars from a
        // dark system setting - which would put white status icons on our
        // white background.
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT),
        )

        // FLAG_SECURE blocks screenshots, screen recording and the
        // recents-screen preview. A password manager that renders credentials
        // must not let any of that leave the display - so it stays on for
        // every shipped build. Debug builds drop it: the release APK would
        // otherwise make store-listing screenshots impossible to capture
        // (screencap returns an empty file), and the debug UI is the same
        // screens users see, so listing images can be taken from it without
        // weakening what users install.
        if (!BuildConfig.DEBUG) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }

        val app = application as VaultApp

        setContent {
            CipherVaultTheme {
                val viewModel: VaultViewModel = viewModel(
                    factory = VaultViewModel.factory(
                        repository = app.repository,
                        biometricAvailable = { app.keystore.keyExists() },
                    ),
                )
                HandleOtpauthIntent(intent, viewModel)
                CipherVaultNav(viewModel)
            }
        }
    }
}

/**
 * Accept an `otpauth://totp/...` link handed over by a QR scanner or browser.
 *
 * Keyed on the URI and remembered across configuration changes, so rotating
 * the device does not re-import a link the user has already acted on, while
 * a genuinely new scan still does. The manifest has advertised this scheme
 * since the first commit — before this it was silently dropped.
 */
@androidx.compose.runtime.Composable
private fun HandleOtpauthIntent(intent: android.content.Intent?, viewModel: VaultViewModel) {
    val uri = intent?.dataString
    // A digest, never the URI: an `otpauth://` link *is* the TOTP seed, and
    // this value is written into the saved-instance-state Bundle the
    // framework persists for process death. Storing the link itself would
    // put a 2FA secret in the exact place VaultViewModel.PendingOtpauth
    // refuses to use. Equality against a digest is all the "have I already
    // acted on this link?" check needs, and it keeps working across rotation
    // and process death.
    //
    // Empty string rather than null: rememberSaveable's auto-Saver is only
    // guaranteed for Bundle-safe values, and String? null handling is not.
    var handledUriDigest by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(uri) {
        if (uri.isNullOrBlank()) return@LaunchedEffect
        if (!uri.startsWith("otpauth:", ignoreCase = true)) return@LaunchedEffect

        val digest = otpauthDigest(uri)
        if (digest == handledUriDigest) return@LaunchedEffect

        handledUriDigest = digest
        // Malformed links are ignored rather than surfaced: the user still
        // gets a working app, and there is no vault to put an error in yet.
        viewModel.importOtpauth(uri)
    }
}

/** SHA-256 of the enrolment link, so the raw seed never enters saved state. */
private fun otpauthDigest(uri: String): String =
    java.security.MessageDigest.getInstance("SHA-256")
        .digest(uri.toByteArray(Charsets.UTF_8))
        .joinToString("") { byte -> "%02x".format(byte) }

private object Routes {
    const val LOADING = "loading"
    const val SETUP = "setup"
    const val LOCK = "lock"
    const val VAULT = "vault"
    const val SCAN = "scan"
    const val ENTRY_PATTERN = "entry/{entryId}"
    fun entry(id: String) = "entry/$id"
}

@androidx.compose.runtime.Composable
private fun CipherVaultNav(viewModel: VaultViewModel) {
    val state by viewModel.state.collectAsState()
    val navController = rememberNavController()

    // Keep the back stack in step with the session: locking or logging out
    // must never leave a vault screen reachable via the back button.
    RouteSync(state, navController)

    // Pull on every return to the foreground. Lives here rather than in the
    // Activity because it needs the ViewModel, which is scoped to this
    // composition.
    ForegroundSync(viewModel)

    // Once the vault is open, drop straight into a prefilled new entry for
    // any `otpauth://` link the user tapped. Guarded by `otpAuthOpened` so a
    // backing-out user is not re-opened into the form again.
    val pendingOtpauth by viewModel.pendingOtpauth.collectAsState()
    var otpAuthOpened by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(pendingOtpauth, state, otpAuthOpened) {
        if (pendingOtpauth == null || otpAuthOpened) return@LaunchedEffect
        if (state !is VaultUiState.Unlocked) return@LaunchedEffect

        // Only when the vault list is what is on screen. A scan started from
        // inside an entry form returns to *that* entry, which consumes the
        // payload itself; opening a second blank form on top would discard
        // the entry the user was halfway through editing.
        val current = navController.currentBackStackEntry?.destination?.route
        if (current != Routes.VAULT) return@LaunchedEffect

        otpAuthOpened = true
        navController.navigate(Routes.entry("new")) { launchSingleTop = true }
    }

    NavHost(navController = navController, startDestination = Routes.LOADING) {
        composable(Routes.LOADING) {
            LoadingScreen()
        }
        composable(Routes.SETUP) {
            SetupScreen(viewModel = viewModel)
        }
        composable(Routes.LOCK) {
            LockScreen(viewModel = viewModel)
        }
        composable(Routes.VAULT) {
            val context = androidx.compose.ui.platform.LocalContext.current
            val app = remember(context) { context.applicationContext as VaultApp }
            UnlockedShell(
                viewModel = viewModel,
                accountEmail = app.repository.accountEmail,
                biometricEnrolled = !app.credentials.wrappedVaultKeyBase64.isNullOrBlank(),
                onOpenEntry = { id -> navController.navigate(Routes.entry(id)) },
                onScanQr = { navController.navigate(Routes.SCAN) },
            )
        }
        composable(Routes.SCAN) {
            QrScannerScreen(
                // Always hand back to wherever the scan was started: the
                // drawer scan lands on the vault list (which then opens a
                // prefilled new entry), an in-form scan lands back on the
                // entry being edited.
                onScanned = { uri ->
                    if (viewModel.importOtpauth(uri)) navController.popBackStack()
                },
                onEnterManually = { navController.popBackStack() },
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.ENTRY_PATTERN) { backStackEntry ->
            val entryId = backStackEntry.arguments?.getString("entryId")
            val unlocked = state as? VaultUiState.Unlocked
            if (entryId == null || unlocked == null) {
                // Entry vanished (deleted on another device) - go back.
                LaunchedEffect(Unit) { navController.popBackStack() }
            } else {
                EntryDetailScreen(
                    entryId = entryId,
                    viewModel = viewModel,
                    onScanQr = { navController.navigate(Routes.SCAN) },
                    onDone = { navController.popBackStack() },
                )
            }
        }
    }
}

/**
 * Foreground behaviour: keep the session honest, and keep the vault fresh.
 *
 * On pause we note the time. On resume we either lock (if the app was away
 * longer than [BACKGROUND_LOCK_AFTER_MS]) or pull the latest vault from the
 * server. Both matter because the vault is no longer dropped the instant the
 * user switches apps — see `VaultApp.onTrimMemory`.
 */
@androidx.compose.runtime.Composable
private fun ForegroundSync(viewModel: VaultViewModel) {
    val lifecycleOwner = LocalLifecycleOwner.current
    var backgroundedAt by remember { mutableStateOf(0L) }

    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_PAUSE -> backgroundedAt = System.currentTimeMillis()

                Lifecycle.Event.ON_RESUME -> {
                    // Capture before clearing: the check below must not see
                    // the zero we just wrote.
                    val startedAt = backgroundedAt
                    backgroundedAt = 0L
                    if (startedAt != 0L &&
                        System.currentTimeMillis() - startedAt > BACKGROUND_LOCK_AFTER_MS
                    ) {
                        // Too long to leave keys in memory unattended.
                        viewModel.lock()
                    } else {
                        // A quick trip to another app: the session survives,
                        // and this is where an edit made elsewhere shows up.
                        viewModel.onAppResumed()
                    }
                }

                else -> Unit
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
}

/**
 * Navigate when the auth state changes, and clear history so an unlocked
 * vault cannot be reached by pressing back after a lock.
 */
@androidx.compose.runtime.Composable
private fun RouteSync(state: VaultUiState, navController: NavHostController) {
    // The state class the back stack was last synchronised to. Saved across
    // recreation so a relaunch does not re-run the wipe: the restored stack
    // already matches the session, and navigating again would popUpTo the
    // restored entry away and push a blank one in its place - which is how a
    // typed email, drawer filter or scroll position used to vanish the
    // instant the phone rotated. Only a real session change needs the wipe.
    var lastSyncedClass by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(state::class) {
        val target = when (state) {
            is VaultUiState.Setup -> Routes.SETUP
            is VaultUiState.Locked -> Routes.LOCK
            is VaultUiState.Unlocked -> Routes.VAULT
            VaultUiState.Loading -> return@LaunchedEffect
        }
        val className = state::class.qualifiedName.orEmpty()

        // Skip only when the class already synced *and* navigation state came
        // back with it; if the back stack failed to restore, sync anyway so
        // the user is not left stranded on the loading screen.
        if (className == lastSyncedClass && navController.currentBackStackEntry != null) {
            return@LaunchedEffect
        }

        navController.navigate(target) {
            // Wipe everything behind, so back exits the app rather than
            // returning to a now-locked screen.
            popUpTo(navController.graph.id) { inclusive = true }
            launchSingleTop = true
        }
        lastSyncedClass = className
    }
}

@androidx.compose.runtime.Composable
private fun LoadingScreen() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center,
    ) {
        CircularProgressIndicator(color = MaterialTheme.colorScheme.primary)
    }
}
