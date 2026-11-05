@file:Suppress("UnstableApiUsage")

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("org.jetbrains.kotlin.jvm")
}

// Keep this module's output under the repository-root build/ directory.
layout.buildDirectory.set(rootProject.layout.buildDirectory.dir("profile-core"))

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    jvmToolchain(25)
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
    }
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

