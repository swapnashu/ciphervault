# ---- Kotlin serialization ----
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

-keepclassmembers class com.sellerbot.ciphervault.** {
    *** Companion;
}
-keepclasseswithmembers class com.sellerbot.ciphervault.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class com.sellerbot.ciphervault.**$$serializer {
    *** INSTANCE;
}

# ---- Retrofit / OkHttp ----
-keepattributes Signature, Exceptions
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
-keepclassmembers,allowshrinking,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}
-dontwarn javax.annotation.**
-dontwarn okhttp3.**
-dontwarn retrofit2.**
-keepclasseswithmembers class * {
    @retrofit2.http.* <methods>;
}

# ---- Crypto ----
# JCA looks up algorithms by string name. Obfuscating these names breaks
# Cipher.getInstance("AES/GCM/NoPadding") and Mac.getInstance("HmacSHA1").
-keep class javax.crypto.** { *; }
-keep class java.security.** { *; }
-dontwarn java.security.**
-dontwarn javax.crypto.**

# Keep our own crypto objects readable in crash reports — losing a stack
# trace inside VaultCipher is exactly the kind of thing you cannot debug later.
-keep class com.sellerbot.ciphervault.crypto.** { *; }
-keep class com.sellerbot.ciphervault.security.** { *; }

# ---- Android Keystore ----
-keep class android.security.keystore.** { *; }
-dontwarn android.security.keystore.**

# ---- General ----
-keepattributes SourceFile, LineNumberTable
-renamesourcefileattribute SourceFile
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**

# ---- Tink (via androidx.security) ----
# Tink is compiled against errorprone's @CanIgnoreReturnValue / @Immutable /
# etc. Those are CLASS-retention compile-time annotations that never ship in
# the release JAR, so the references can only ever warn - never fail - at
# runtime.
-dontwarn com.google.errorprone.annotations.CanIgnoreReturnValue
-dontwarn com.google.errorprone.annotations.CheckReturnValue
-dontwarn com.google.errorprone.annotations.Immutable
-dontwarn com.google.errorprone.annotations.RestrictedApi
