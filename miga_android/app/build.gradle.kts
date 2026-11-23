import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val protocolJniDir = rootProject.layout.projectDirectory.dir("../Build/android/jni")

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
        versionCode = 5
        versionName = "1.3.0"
        testInstrumentationRunner = "org.miga.android.NativeLoadInstrumentation"
    }
    sourceSets.getByName("androidTest").kotlin.directories.add(layout.buildDirectory.dir("generated/directTests").get().asFile.absolutePath)
    sourceSets.getByName("main").jniLibs.directories.apply {
        clear()
        add(protocolJniDir.asFile.absolutePath)
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
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
}

val protocolNativeInputs = rootProject.fileTree("..") {
    include("miga_android/build-v2.py", "miga_android/app/src/main/cpp/ProtocolV2Jni.cpp")
    include("miga_client/src/ProtocolV2Session.cpp", "miga_client/include/ProtocolV2Session.h")
    include("Shared/ProtocolV2.*", "Shared/ProtocolV2Packets.*", "Shared/InternetChecksum.*", "Shared/nlohmann/**/*.hpp")
    include("dependencies/manifest.json", "dependencies/libsodium-*.tar.gz", "dependencies/noise-c-*.tar.gz")
}
val protocolAbis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
val repositoryDir = rootProject.projectDir.parentFile

fun nativeDigest(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { stream ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            val count = stream.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

val verifyProtocolV2Libraries = tasks.register("verifyProtocolV2Libraries") {
    inputs.files(protocolNativeInputs)
    inputs.files(protocolAbis.flatMap { abi ->
        listOf(protocolJniDir.file("$abi/libmiga-v2.so"), protocolJniDir.file("$abi/libmiga-v2.sha256"), protocolJniDir.file("$abi/libhev-socks5-tunnel.so"))
    })
    doLast {
        val expected = protocolNativeInputs.files.associate {
            it.relativeTo(repositoryDir).invariantSeparatorsPath to nativeDigest(it)
        }
        protocolAbis.forEach { abi ->
            val directory = protocolJniDir.dir(abi)
            val binary = directory.file("libmiga-v2.so").asFile
            val stamp = directory.file("libmiga-v2.sha256").asFile
            check(directory.file("libhev-socks5-tunnel.so").asFile.isFile) { "Run build-hev.ps1 to build the HEV library for $abi." }
            val instruction = "Run build-v2.py with the installed NDK before packaging."
            check(binary.isFile && stamp.isFile) { "Missing v2 library or build stamp for $abi. $instruction" }
            val recorded = stamp.readLines().associate { line -> line.substringAfter(' ') to line.substringBefore(' ') }
            check(recorded == expected + (binary.name to nativeDigest(binary))) {
                "Stale v2 library for $abi. $instruction"
            }
        }
    }
}
tasks.named("preBuild") { dependsOn(verifyProtocolV2Libraries) }

val prepareDirectDeviceTests = tasks.register<Sync>("prepareDirectDeviceTests") {
    from("../core/src/test/kotlin") { include("**/LocalDirectSocks*Test.kt") }
    into(layout.buildDirectory.dir("generated/directTests"))
}
tasks.matching { it.name == "preDebugAndroidTestBuild" }.configureEach { dependsOn(prepareDirectDeviceTests) }
