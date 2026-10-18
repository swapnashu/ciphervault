plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

// Release signing, read from `keystore.properties` (git-ignored) so no
// passphrase ever lives in this script or in version control. When the file
// is absent - a fresh clone, or a machine that must not sign - the release
// build type is left unsigned rather than silently falling back to the debug
// key, which would make a throwaway build indistinguishable from a shippable
// one.
//
// Parsed by hand rather than with java.util.Properties: in a Gradle Kotlin
// DSL script the bare name `java` resolves to the project's java extension,
// not to the package, so `java.util.Properties` does not compile here.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties: Map<String, String> =
    if (keystorePropertiesFile.exists()) {
        keystorePropertiesFile.readLines()
            .filter { it.isNotBlank() && !it.trimStart().startsWith("#") }
            .mapNotNull { line ->
                val separator = line.indexOf('=')
                if (separator < 0) return@mapNotNull null
                line.substring(0, separator).trim() to line.substring(separator + 1).trim()
            }
            .toMap()
    } else {
        emptyMap()
    }

android {
    namespace = "com.sellerbot.ciphervault"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.sellerbot.ciphervault"
        minSdk = 26
        targetSdk = 34
        versionCode = 2
        versionName = "0.1.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // Production URL. The debug build type overrides this with a local
        // emulator-only address so a version-matched server can be exercised
        // without touching real accounts.
        buildConfigField("String", "API_BASE_URL", "\"https://sellerbots.pythonanywhere.com/vault/api/\"")

        // ML Kit's bundled barcode decoder (`libbarhopper_v3.so`) is ~5-6 MB
        // per ABI. Shipping all four costs about 20 MB of the APK for ABIs
        // nothing here runs on. arm64 covers the physical handset; x86_64
        // keeps the emulator usable for development.
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (keystorePropertiesFile.exists()) {
            create("release") {
                storeFile = file(keystoreProperties.getValue("storeFile"))
                storePassword = keystoreProperties["storePassword"]
                keyAlias = keystoreProperties.getValue("keyAlias")
                keyPassword = keystoreProperties["keyPassword"]
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"

            // The emulator reaches the host machine through the special
            // alias 10.0.2.2. Pointing debug builds here (rather than the
            // pinned production host) lets the full register/login/sync flow
            // run against a local, version-matched server. `debug/res/xml/
            // network_security_config.xml` permits cleartext to this address
            // only, so a debug build cannot silently downgrade production
            // traffic. Release keeps BuildConfig.API_BASE_URL above.
            buildConfigField(
                "String",
                "API_BASE_URL",
                "\"http://10.0.2.2:5000/vault/api/\""
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
    }
}

dependencies {
    // Core
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)

    // Compose
    // The BOM must be applied to every configuration that pulls a Compose
    // artifact, otherwise unversioned entries (ui-test-manifest, ui-test-junit4)
    // resolve with an empty version and lint/assemble fail on the androidTest classpath.
    implementation(platform(libs.androidx.compose.bom))
    debugImplementation(platform(libs.androidx.compose.bom))
    testImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.navigation.compose)
    debugImplementation(libs.androidx.ui.tooling)

    // Security
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.datastore.preferences)

    // Argon2id (memory-hard KDF) via Bouncy Castle pure-Java provider.
    // No native libs; slower than JNI but zero supply-chain surface.
    implementation(libs.bcprov.jdk18on)

    // Camera + on-device barcode scanning for authenticator QR enrolment.
    //
    // The *bundled* ML Kit artifact (`com.google.mlkit:barcode-scanning`, not
    // `play-services-mlkit:barcode-scanning`) is deliberate: it carries its

    // QR code generation for sharing 2FA entries
    implementation("com.google.zxing:core:3.5.2")
    // own model and talks to no network, so no part of a zero-knowledge vault
    // gains a dependency on Google Play services.
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.mlkit.barcode.scanning)

    // Networking + JSON
    implementation(libs.retrofit)
    implementation(libs.retrofit.kotlinx.serialization)
    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    implementation(libs.kotlinx.serialization.json)

    // Testing - mirrors the Python RFC 6238 vectors
    testImplementation(libs.junit)
    testImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.compose.ui.test.manifest)
}
