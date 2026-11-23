plugins { id("com.android.application") }

android {
    namespace = "org.miga.android.devicechecks"
    compileSdk = 37
    defaultConfig {
        applicationId = "org.miga.android.devicechecks"
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"
    }
    sourceSets.getByName("main").kotlin.directories.add(layout.buildDirectory.dir("generated/checks").get().asFile.absolutePath)
    sourceSets.getByName("main").jniLibs.directories.apply {
        clear()
        add(rootProject.file("../Build/android/jni").absolutePath)
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":core"))
    implementation("junit:junit:4.13.2")
}

val prepareChecks = tasks.register<Sync>("prepareChecks") {
    from("../core/src/test/kotlin") { include("**/LocalDirectSocks*Test.kt") }
    from("../app/src/androidTest/kotlin") { include("**/NativeLoadInstrumentation.kt") }
    from("../app/src/main/kotlin") { include("**/ProtocolV2Native.kt", "**/TProxyService.kt") }
    into(layout.buildDirectory.dir("generated/checks"))
}
tasks.named("preBuild") { dependsOn(prepareChecks, ":app:verifyProtocolV2Libraries") }
