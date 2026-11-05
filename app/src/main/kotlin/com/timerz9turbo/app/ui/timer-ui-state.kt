package com.timerz9turbo.app.ui

import com.timerz9turbo.app.data.ManagerScanner
import com.timerz9turbo.app.domain.model.LogEntry
import com.timerz9turbo.app.domain.model.ShizukuStatus

data class TimerUiState(
    val deviceName: String = "",
    val kernelRelease: String = "",
    val socName: String = "",
    val androidVersion: String = "",
    val kernelSupported: Boolean = false,
    val shizukuStatus: ShizukuStatus = ShizukuStatus.NOT_RUNNING,
    val running: Boolean = false,
    val safeModeEnabled: Boolean = false,
    val executionSheetVisible: Boolean = false,
    val executionSheetDismissible: Boolean = false,
    val logLines: List<LogEntry> = emptyList(),
    val advancedScreenVisible: Boolean = false,
    val aboutVisible: Boolean = false,
    val debugExportEnabled: Boolean = true,
    val debugExportLocation: String = "",
    val managerCandidates: List<ManagerScanner.Candidate> = emptyList(),
    val selectedManagerPackage: String? = null,
    val managerPickerVisible: Boolean = false,
)

interface TimerActions {
    fun onRun()
    fun onRunDiagnose()
    fun onStatusClick()
    fun onCloseExecutionSheet()
    fun onCopyLogs()
    fun onSafeModeChanged(enabled: Boolean)
    fun onOpenManagerPicker()
    fun onCloseManagerPicker()
    fun onManagerSelected(pkg: String?)
    fun onOpenAdvanced()
    fun onCloseAdvanced()
    fun onShowAbout()
    fun onCloseAbout()
    fun onDebugExportChanged(enabled: Boolean)
    fun onDebugExportLocationPick()
}

sealed interface TimerEffect {
    data object PickDebugFolder : TimerEffect
    data class Toast(val resourceId: Int) : TimerEffect
    data class Clipboard(val text: String) : TimerEffect
    data class KeepScreenAwake(val enabled: Boolean) : TimerEffect
    data object OpenShizuku : TimerEffect
}
