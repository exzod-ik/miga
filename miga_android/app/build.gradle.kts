plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val releaseStorePath = providers.environmentVariable("MIGA_RELEASE_STORE_FILE").orNull
val releaseStorePassword = providers.environmentVariable("MIGA_RELEASE_STORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("MIGA_RELEASE_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("MIGA_RELEASE_KEY_PASSWORD").orNull
val releaseSigningValues = listOf(releaseStorePath, releaseStorePassword, releaseKeyAlias, releaseKeyPassword)
val releaseSigningEnabled = releaseSigningValues.all { !it.isNullOrBlank() }
check(releaseSigningValues.none { !it.isNullOrBlank() } || releaseSigningEnabled) {
    "Set all four MIGA_RELEASE_* environment variables to sign the release APK."
}

android {
    namespace = "org.miga.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.miga.android"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0"
        testInstrumentationRunner = "org.miga.android.NativeLoadInstrumentation"
    }
    buildFeatures { compose = true }
    val releaseSigningConfig = if (releaseSigningEnabled) {
        signingConfigs.create("release") {
            storeFile = file(requireNotNull(releaseStorePath))
            storePassword = requireNotNull(releaseStorePassword)
            keyAlias = requireNotNull(releaseKeyAlias)
            keyPassword = requireNotNull(releaseKeyPassword)
        }
    } else null
    buildTypes {
        getByName("release") {
            signingConfig = releaseSigningConfig
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":core"))
    implementation(platform("androidx.compose:compose-bom:2026.02.01"))
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.activity:activity-ktx:1.8.2")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.datastore:datastore-preferences:1.2.1")
    implementation("com.github.mwiede:jsch:2.28.7")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
}
