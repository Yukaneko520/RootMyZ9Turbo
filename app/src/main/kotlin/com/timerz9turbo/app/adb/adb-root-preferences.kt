package com.timerz9turbo.app.adb

import android.content.Context
import androidx.core.content.edit
import com.timerz9turbo.app.domain.model.AdbRootSettings

internal class AdbRootPreferences(context: Context) {
    private companion object {
        const val FILE = "adb_root_prefs"
        const val KEY_MANUAL = "manual_enabled"
        const val KEY_SETUP_COMPLETE = "setup_complete"
        const val KEY_KEY_REJECTED = "key_rejected"
        const val KEY_KEY_AUTHORIZED = "key_authorized"
    }

    private val appContext = context.applicationContext
    private val storageContext = runCatching {
        val de = appContext.createDeviceProtectedStorageContext()
        if (!de.getSharedPreferences(FILE, Context.MODE_PRIVATE).contains(KEY_MANUAL)) {
            runCatching { de.moveSharedPreferencesFrom(appContext, FILE) }
        }
        de
    }.getOrNull() ?: appContext
    private val prefs = storageContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    var manualAdbEnabled: Boolean
        get() = prefs.getBoolean(KEY_MANUAL, false)
        set(value) = prefs.edit { putBoolean(KEY_MANUAL, value) }

    var setupComplete: Boolean
        get() = prefs.getBoolean(KEY_SETUP_COMPLETE, false)
        set(value) = prefs.edit { putBoolean(KEY_SETUP_COMPLETE, value) }

    /** True after the user rejected the prompt; the next try restarts adbd. */
    var keyRejected: Boolean
        get() = prefs.getBoolean(KEY_KEY_REJECTED, false)
        set(value) = prefs.edit { putBoolean(KEY_KEY_REJECTED, value) }

    /** Persisted confirmation that the key was authorized by adbd / system_server. */
    var keyAuthorized: Boolean
        get() = prefs.getBoolean(KEY_KEY_AUTHORIZED, false)
        set(value) = prefs.edit { putBoolean(KEY_KEY_AUTHORIZED, value) }

    fun settings() = AdbRootSettings(
        manualEnabled = manualAdbEnabled,
        setupComplete = setupComplete,
        keyAuthorized = keyAuthorized,
    )
}
