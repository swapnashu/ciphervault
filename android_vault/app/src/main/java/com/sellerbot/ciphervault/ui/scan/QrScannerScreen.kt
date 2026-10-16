package com.sellerbot.ciphervault.ui.scan

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.NoPhotography
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.sellerbot.ciphervault.R
import java.util.concurrent.Executors

/**
 * Live camera scanner for `otpauth://` QR codes.
 *
 * The camera is bound only for as long as this screen is on top. Nothing is
 * recorded, no image leaves `ImageAnalysis`, and the preview is drawn behind
 * `FLAG_SECURE`'s window, so a screen recorder captures black.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScannerScreen(
    onScanned: (String) -> Unit,
    onEnterManually: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current

    var hasPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted -> hasPermission = granted }

    var scanError by remember { mutableStateOf<String?>(null) }

    BackHandler(onBack = onBack)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scan_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                ),
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onEnterManually) {
                        Icon(Icons.Filled.Keyboard, contentDescription = "Enter secret manually")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when {
                !hasPermission -> PermissionRationale(
                    onRequest = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                    onEnterManually = onEnterManually,
                )

                else -> CameraPreview(
                    modifier = Modifier.weight(1f),
                    onScanned = onScanned,
                    onError = { scanError = it },
                )
            }

            scanError?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 8.dp),
                )
            }

            Text(
                text = stringResource(R.string.scan_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 16.dp),
            )

            OutlinedButton(
                onClick = onEnterManually,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp)
                    .padding(bottom = 24.dp),
            ) {
                Icon(Icons.Filled.Keyboard, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
                Text(stringResource(R.string.scan_manual))
            }
        }
    }
}

/**
 * Camera + preview, bound to this screen's lifecycle and unbound on dispose.
 *
 * Both bindings are torn down in [DisposableEffect]'s `onDispose`: leaving the
 * camera running after the screen is gone keeps the sensor powered and the
 * torch indicator lit on devices that default the flash on.
 */
@Composable
private fun CameraPreview(
    modifier: Modifier = Modifier,
    onScanned: (String) -> Unit,
    onError: (String) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val executor = remember { Executors.newSingleThreadExecutor() }

    val previewView = remember {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())

        val cutoutColor = MaterialTheme.colorScheme.outline
        androidx.compose.foundation.Canvas(modifier = Modifier.fillMaxSize()) {
            val side = size.minDimension * 0.78f
            val left = (size.width - side) / 2f
            val top = (size.height - side) / 2f
            val corner = CornerRadius(28f, 28f)

            // Even-odd fill: a full-screen rect minus the rounded cutout is
            // the scrim, so the code sits in a clear window rather than
            // being darkened along with everything around it.
            val scrim = Path().apply {
                addRect(Rect(0f, 0f, size.width, size.height))
                addRoundRect(
                    androidx.compose.ui.geometry.RoundRect(
                        left = left,
                        top = top,
                        right = left + side,
                        bottom = top + side,
                        cornerRadius = corner,
                    ),
                )
                fillType = PathFillType.EvenOdd
            }
            drawPath(scrim, color = Color.Black.copy(alpha = 0.62f))

            drawRoundRect(
                color = cutoutColor,
                topLeft = Offset(left, top),
                size = Size(side, side),
                cornerRadius = corner,
                style = Stroke(width = 4f),
            )
        }
    }

    DisposableEffect(lifecycleOwner, executor) {
        var bound = false
        val future = ProcessCameraProvider.getInstance(context)

        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
            }

            // Analyzer runs off the main thread; the preview stream and the
            // UI both stay responsive while frames are being decoded.
            val analyzer = BarcodeAnalyzer(onQrContent = onScanned)
            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also { it.setAnalyzer(executor, analyzer) }

            try {
                provider.unbindAll()
                provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
                bound = true
            } catch (t: Exception) {
                // No back camera, or another app holds the sensor.
                onError("Could not open the camera")
            }
        }, ContextCompat.getMainExecutor(context))

        onDispose {
            runCatching { ProcessCameraProvider.getInstance(context).get().unbindAll() }
            executor.shutdown()
        }
    }
}

@Composable
private fun PermissionRationale(
    onRequest: () -> Unit,
    onEnterManually: () -> Unit,
) {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            contentAlignment = Alignment.Center,
            modifier = Modifier
                .size(88.dp)
                .border(2.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(24.dp)),
        ) {
            Icon(
                imageVector = Icons.Filled.NoPhotography,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(36.dp),
            )
        }

        Spacer(Modifier.height(20.dp))

        Text(
            text = stringResource(R.string.scan_permission_title),
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
        )

        Spacer(Modifier.height(8.dp))

        Text(
            text = stringResource(R.string.scan_permission_body),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        Spacer(Modifier.height(24.dp))

        Button(onClick = onRequest) {
            Text(stringResource(R.string.scan_permission_allow))
        }

        Spacer(Modifier.height(12.dp))

        TextButtonish(
            text = stringResource(R.string.scan_manual),
            onClick = onEnterManually,
        )

        Spacer(Modifier.height(12.dp))

        // Not every OEM surfaces the permission dialog a second time; a
        // direct jump to the app's settings page is the reliable route.
        TextButtonish(
            text = stringResource(R.string.scan_open_app_settings),
            onClick = {
                runCatching {
                    context.startActivity(
                        Intent(
                            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            Uri.fromParts("package", context.packageName, null),
                        ),
                    )
                }
            },
        )
    }
}

@Composable
private fun TextButtonish(text: String, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick) {
        Text(text)
    }
}
