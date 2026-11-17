package com.timerz9turbo.app.adb

import android.content.Context
import com.timerz9turbo.app.data.TimerRepository
import com.timerz9turbo.app.domain.model.AdbRootSettings
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AdbResetSetupTest {
    private lateinit var context: Context
    private lateinit var preferences: AdbRootPreferences
    private lateinit var keys: AdbKeyManager
    private lateinit var connection: AdbConnectionManager
    private lateinit var setup: AdbSetupManager

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("adb_root_prefs", Context.MODE_PRIVATE).edit().clear().commit()
        preferences = AdbRootPreferences(context)
        keys = AdbKeyManager(context)
        connection = AdbConnectionManager(context, preferences, keys)
        setup = AdbSetupManager(context, preferences, keys, connection, suRunner = { ShellResult(0, "") })
    }

    @Test
    fun `resetSetup clears setupComplete and executes successfully with root`() = runBlocking {
        preferences.setupComplete = true
        assertTrue(preferences.setupComplete)

        val result = setup.resetSetup()
        assertTrue(result.ok)
        assertFalse(preferences.setupComplete)
    }

    @Test
    fun `resetSetup fails when root is not available`() = runBlocking {
        val noRootSetup = AdbSetupManager(
            context,
            preferences,
            keys,
            connection,
            suRunner = { ShellResult(-1, "su: not found") },
        )
        preferences.setupComplete = true

        val result = noRootSetup.resetSetup()
        assertFalse(result.ok)
        assertTrue(result.detail.contains("su: not found"))
    }

    @Test
    fun `applyPersistPort fails when root is not available`() = runBlocking {
        val noRootSetup = AdbSetupManager(
            context,
            preferences,
            keys,
            connection,
            suRunner = { ShellResult(-1, "Permission denied") },
        )
        val result = noRootSetup.applyPersistPort()
        assertFalse(result.ok)
        assertTrue(result.detail.contains("Permission denied"))
    }

    @Test
    fun `applyPersistPort succeeds when root is available`() = runBlocking {
        val result = setup.applyPersistPort()
        assertTrue(result.ok)
    }

    @Test
    fun `snapshot after reset reflects incomplete setup`() = runBlocking {
        preferences.setupComplete = true
        setup.resetSetup()

        val snapshot = setup.snapshot()
        assertFalse(snapshot.setupComplete)
        assertFalse(preferences.setupComplete)
    }

    @Test
    fun `manual switch toggle persists directly without root check`() {
        val repository = TimerRepository(context, suRunner = { ShellResult(0, "") })
        assertFalse(repository.adbSettings().manualEnabled)

        repository.setAdbManualEnabled(true)
        assertTrue(repository.adbSettings().manualEnabled)

        repository.setAdbManualEnabled(false)
        assertFalse(repository.adbSettings().manualEnabled)
    }

    @Test
    fun `resetSetup via TimerRepository resets configuration with root`() = runBlocking {
        val repository = TimerRepository(context, suRunner = { ShellResult(0, "") })
        preferences.setupComplete = true
        assertTrue(preferences.setupComplete)

        val actionResult = repository.adbResetSetup()
        assertTrue(actionResult.ok)
        assertFalse(preferences.setupComplete)

        val refreshed = repository.adbRefreshSetup()
        assertFalse(refreshed.setupComplete)
    }

    @Test
    fun `AdbRootSettings contains only streamlined fields`() {
        val settings = AdbRootSettings(
            manualEnabled = true,
            setupComplete = false,
            keyAuthorized = true,
        )
        assertTrue(settings.manualEnabled)
        assertFalse(settings.setupComplete)
        assertTrue(settings.keyAuthorized)
    }
}
