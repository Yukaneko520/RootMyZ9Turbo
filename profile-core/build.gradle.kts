@file:Suppress("UnstableApiUsage")

plugins {
    id("org.jetbrains.kotlin.jvm")
}

// Keep this module's output under the repository-root build/ directory.
layout.buildDirectory.set(rootProject.layout.buildDirectory.dir("profile-core"))

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation("com.typesafe:config:1.4.3")
    testImplementation("junit:junit:4.13.2")
}

/**
 * Serializes every bundled HOCON kernel profile into the v2 binary layout the
 * native side reads. The exporter runs the same [ProfileMerger] /
 * [ProfileResolver] / `NativeProfileDocument` code as the app.
 */

