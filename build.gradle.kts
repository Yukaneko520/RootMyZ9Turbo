plugins {
    id("com.android.application") version "9.1.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}

tasks.register<Delete>("clean") {
    description = "Delete all module outputs under the root build directory."
    delete(layout.buildDirectory)
}
