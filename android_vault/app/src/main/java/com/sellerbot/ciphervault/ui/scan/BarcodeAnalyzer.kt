package com.sellerbot.ciphervault.ui.scan

import android.annotation.SuppressLint
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.atomic.AtomicBoolean

/**
 * ML Kit QR reader bridged onto CameraX's analysis stream.
 *
 * Deliberately narrow: `FORMAT_QR_CODE` only, because an authenticator seed
 * never arrives as a PDF417 boarding pass and restricting the format keeps
 * the per-frame cost low enough to run at 640x480 without dropping the
 * device into thermal throttling.
 *
 * The bundled ML Kit client owns no network path — see the dependency note
 * in `build.gradle.kts` — so the scanned value is only ever handed to the
 * caller, never observed by anything else.
 */
class BarcodeAnalyzer(
    private val onQrContent: (String) -> Unit,
) : ImageAnalysis.Analyzer {

    private val scanner = BarcodeScanning.getClient(
        BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build(),
    )

    /**
     * Guards against delivering the same frame twice.
     *
     * `onQrContent` navigates away, but the analysis stream keeps producing
     * frames for a beat while that transition runs; without this a single
     * scan could fire the callback several times and race two destinations.
     */
    private val delivered = AtomicBoolean(false)

    @SuppressLint("UnsafeOptInUsageError")
    override fun analyze(imageProxy: ImageProxy) {
        if (delivered.get()) {
            imageProxy.close()
            return
        }

        val mediaImage = imageProxy.image
        if (mediaImage == null) {
            imageProxy.close()
            return
        }

        // Rotation is applied here rather than being baked into the target,
        // so a device held at any angle still decodes.
        val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)

        scanner.process(image)
            .addOnSuccessListener { barcodes ->
                val raw = barcodes.firstNotNullOfOrNull { it.rawValue?.takeIf(String::isNotBlank) }
                if (raw != null && delivered.compareAndSet(false, true)) {
                    onQrContent(raw)
                }
            }
            // Always close, including on failure: a stuck frame would stall
            // the whole analysis pipeline and freeze the preview.
            .addOnCompleteListener { imageProxy.close() }
    }

    fun close() {
        runCatching { scanner.close() }
    }
}
