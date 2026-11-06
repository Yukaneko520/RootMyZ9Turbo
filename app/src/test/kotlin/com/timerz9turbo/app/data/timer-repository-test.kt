package com.timerz9turbo.app.data

import android.content.Context
import android.net.Uri
import com.timerz9turbo.app.domain.model.DebugSettings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowBuild

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class TimerRepositoryTest {
    @Test
    fun `selected log folder retains its URI and access permission`() {
        val context = RuntimeEnvironment.getApplication()
        val tree = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3AZ9tb")
        val first = TimerRepository(context)
        try {
            first.setDebugExportLocation("Z9tb", tree.toString())
        } finally { first.close() }
        val second = TimerRepository(context)
        try {
            assertEquals("Z9tb", second.debugSettings().exportLocation)
            val prefs = context.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
            assertEquals(tree.toString(), prefs.getString("debug_export_tree_uri", null))
            val permission = context.contentResolver.persistedUriPermissions.single { it.uri == tree }
            assertTrue(permission.isReadPermission && permission.isWritePermission)
            second.setDebugExportLocation("Download/Timer")
            assertNull(prefs.getString("debug_export_tree_uri", null))
        } finally { second.close() }
    }

    @Test
    fun `manager and export preferences survive repository recreation`() {
        val context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE).edit().clear()
            .putString("manager_package", "com.sukisu.ultra").commit()
        val first = TimerRepository(context)
        try {
            assertEquals("com.sukisu.ultra", first.selectedManagerPackage())
            first.setDebugExportLocation("Download/Timer")
            first.setDebugExportEnabled(false)
        } finally { first.close() }
        val second = TimerRepository(context)
        try {
            assertEquals("com.sukisu.ultra", second.selectedManagerPackage())
            assertEquals(DebugSettings(false, "Download/Timer"), second.debugSettings())
        } finally { second.close() }
    }

    @Test
    fun `device support does not depend on removed profiles`() {
        ShadowBuild.setDevice("PD2352")
        val repository = TimerRepository(RuntimeEnvironment.getApplication())
        try {
            assertTrue(repository.snapshot().kernelSupported)
            repository.setSafeModeEnabled(true)
            assertTrue(repository.snapshot().safeModeEnabled)
            ShadowBuild.setDevice("unrelated-device")
            ShadowBuild.setProduct("unrelated-product")
            ShadowBuild.setModel("unrelated-model")
            assertFalse(repository.snapshot().kernelSupported)
        } finally { repository.close() }
    }

    @Test
    fun `export location rejects traversal and normalizes repeated separators`() {
        assertEquals("Download/Timer", normalizeDebugLocation(" /Download//Timer/ "))
        assertEquals(DebugSettings().exportLocation, normalizeDebugLocation("Download/../other"))
        assertEquals(DebugSettings().exportLocation, normalizeDebugLocation(null))
    }
}
