pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
    resolutionStrategy.eachPlugin {
        if (requested.id.id == "org.jetbrains.kotlin.jvm")
            useModule("org.jetbrains.kotlin:kotlin-gradle-plugin:${requested.version}")
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "miga_android"
include(":app", ":core")
