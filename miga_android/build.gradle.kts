plugins {
    id("com.android.application") version "9.4.1" apply false
    id("org.jetbrains.kotlin.jvm") version "2.2.10" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
}

val buildRoot = rootProject.projectDir.parentFile.resolve("Build")
val work = providers.environmentVariable("MIGA_ANDROID_WORKSPACE").orNull?.let(::File)

allprojects {
    layout.buildDirectory.set((work ?: buildRoot.resolve(".work/android-ide")).resolve(project.name))
}
