package com.timerz9turbo.app.data

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import java.io.File

/** Finds root-manager candidates and orders them for ksud resolution. */
object ManagerScanner {
    const val PREF_KEY = "manager_package"

    /** Known KernelSU-family managers, prioritized in the picker. */
    val BUILTIN = listOf(
        "me.weishu.kernelsu.pr",
        "me.weishu.kernelsu",
        "com.resukisu.resukisu",
        "org.bakasu.bakasu",
        "com.kowx712.supermanager",
        "com.sukisu.ultra",
    )

    data class Candidate(
        val packageName: String,
        val label: String,
        val hasKsud: Boolean,
        val builtin: Boolean,
    )

    /**
     * Fast filename-only scan; binary inspection is reserved for the selected manager.
     * All non-system apps, compatible first. Relies on QUERY_ALL_PACKAGES;
     * if that permission is ever dropped, filter to BUILTIN here.
     */
    @Suppress("DEPRECATION")
    fun scan(pm: PackageManager, selfPackage: String): List<Candidate> =
        pm.getInstalledPackages(0)
            .asSequence()
            .mapNotNull { pi -> pi.applicationInfo?.let { pi to it } }
            .filter { (pi, _) -> pi.packageName != selfPackage }
            .filter { (_, ai) -> (ai.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
            .map { (pi, ai) ->
                val dir = ai.nativeLibraryDir
                Candidate(
                    packageName = pi.packageName,
                    label = ai.loadLabel(pm).toString(),
                    hasKsud = dir != null && File(dir, "libksud.so").isFile,
                    builtin = pi.packageName in BUILTIN,
                )
            }
            .sortedWith(sortComparator())
            .toList()

    /** Pure sort, extracted so it is testable without a PackageManager. */
    fun sortComparator() = compareByDescending<Candidate> { it.builtin && it.hasKsud }
        .thenByDescending { it.hasKsud }
        .thenBy { it.label.lowercase() }

    data class ResolvedKsud(val packageName: String, val file: File)

    /** Never substitute another manager for the user's explicit selection. */
    fun resolveKsud(pm: PackageManager, chosen: String?): ResolvedKsud? {
        val packageName = chosen?.takeIf { it.isNotBlank() } ?: return null
        return runCatching {
            KsudLibrary.find(pm.getApplicationInfo(packageName, 0).nativeLibraryDir)
                ?.let { ResolvedKsud(packageName, it) }
        }.getOrNull()
    }
}
