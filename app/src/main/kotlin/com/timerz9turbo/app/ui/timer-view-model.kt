package com.timerz9turbo.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.timerz9turbo.app.R
import com.timerz9turbo.app.data.TimerRepository
import com.timerz9turbo.app.domain.model.ShizukuStatus
import com.timerz9turbo.app.domain.usecase.FormatLogUseCase
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class TimerViewModel(private val repository: TimerRepository) : ViewModel(), TimerActions {
    private val mutableState = MutableStateFlow(TimerUiState())
    private val effectChannel = Channel<TimerEffect>(Channel.BUFFERED)
    private val formatLog = FormatLogUseCase()
    private var initialized = false
    val state = mutableState.asStateFlow()
    val effects = effectChannel.receiveAsFlow()

    fun initialize() {
        if (initialized) return
        initialized = true
        repository.setShizukuStatusListener(::refreshAccessStatus)
        repository.requestShizukuPermission()
        refreshAccessStatus()
    }

    fun refreshAccessStatus() {
        viewModelScope.launch(Dispatchers.IO) {
            val snapshot = repository.snapshot()
            val settings = repository.debugSettings()
            mutableState.update { it.copy(
                deviceName = snapshot.deviceName, kernelRelease = snapshot.kernelRelease,
                socName = snapshot.socName, androidVersion = snapshot.androidVersion,
                kernelSupported = snapshot.kernelSupported, safeModeEnabled = snapshot.safeModeEnabled,
                shizukuStatus = snapshot.shizukuStatus, selectedManagerPackage = repository.selectedManagerPackage(),
                debugExportEnabled = settings.exportEnabled, debugExportLocation = settings.exportLocation,
            ) }
        }
    }

    override fun onStatusClick() {
        when (state.value.shizukuStatus) {
            ShizukuStatus.NOT_RUNNING -> send(TimerEffect.OpenShizuku)
            ShizukuStatus.PERMISSION_REQUIRED -> repository.requestShizukuPermission()
            ShizukuStatus.READY -> Unit
        }
    }

    override fun onRun() = run(diagnose = false)
    override fun onRunDiagnose() = run(diagnose = true)

    private fun run(diagnose: Boolean) {
        val current = state.value
        if (current.running) return
        if (!diagnose && !current.kernelSupported) return
        if (current.shizukuStatus != ShizukuStatus.READY) { onStatusClick(); return }
        if (!diagnose && current.selectedManagerPackage.isNullOrBlank()) {
            send(TimerEffect.Toast(R.string.su_required))
            return
        }
        mutableState.update { it.copy(running = true, executionSheetVisible = true, executionSheetDismissible = false) }
        send(TimerEffect.KeepScreenAwake(true))
        appendLog(if (diagnose) "==== diagnose (timer ids, no UAF) ====" else "==== start Timer/Shizuku ====")
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val code = repository.run(diagnose, ::appendLog)
                appendLog(if (code == 0) "result: completed" else "result: failed (exit code=$code)")
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                appendLog("result: failed (${error.message})")
            } finally {
                mutableState.update { it.copy(running = false, executionSheetDismissible = true) }
                send(TimerEffect.KeepScreenAwake(false))
            }
        }
    }

    override fun onCloseExecutionSheet() {
        if (state.value.executionSheetDismissible) mutableState.update { it.copy(executionSheetVisible = false) }
    }

    override fun onCopyLogs() {
        send(TimerEffect.Clipboard(state.value.logLines.joinToString("") { it.text }))
        send(TimerEffect.Toast(R.string.copied))
    }

    override fun onSafeModeChanged(enabled: Boolean) {
        repository.setSafeModeEnabled(enabled)
        mutableState.update { it.copy(safeModeEnabled = enabled) }
    }

    override fun onOpenManagerPicker() {
        mutableState.update { it.copy(managerPickerVisible = true) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { repository.installedManagers() }
                .onSuccess { managers -> mutableState.update { it.copy(managerCandidates = managers) } }
                .onFailure { appendLog("<k> error: cannot scan managers: ${it.message}") }
        }
    }

    override fun onCloseManagerPicker() { mutableState.update { it.copy(managerPickerVisible = false) } }
    override fun onManagerSelected(pkg: String?) {
        repository.setSelectedManagerPackage(pkg)
        mutableState.update { it.copy(selectedManagerPackage = pkg, managerPickerVisible = false) }
    }
    override fun onOpenAdvanced() { mutableState.update { it.copy(advancedScreenVisible = true) } }
    override fun onCloseAdvanced() { mutableState.update { it.copy(advancedScreenVisible = false, aboutVisible = false) } }
    override fun onShowAbout() { mutableState.update { it.copy(aboutVisible = true) } }
    override fun onCloseAbout() { mutableState.update { it.copy(aboutVisible = false) } }
    override fun onDebugExportChanged(enabled: Boolean) {
        repository.setDebugExportEnabled(enabled)
        mutableState.update { it.copy(debugExportEnabled = enabled) }
    }
    override fun onDebugExportLocationPick() = send(TimerEffect.PickDebugFolder)
    fun onDebugExportLocationPicked(location: String?) {
        if (location == null) { send(TimerEffect.Toast(R.string.debug_export_location_unsupported)); return }
        repository.setDebugExportLocation(location)
        mutableState.update { it.copy(debugExportLocation = repository.debugSettings().exportLocation) }
    }

    private fun appendLog(line: String) {
        val tagged = if (line.startsWith("result:")) "<k> $line" else line
        val entry = formatLog(tagged)
        mutableState.update { it.copy(logLines = it.logLines + entry) }
    }
    private fun send(effect: TimerEffect) { effectChannel.trySend(effect) }
    override fun onCleared() {
        repository.close()
        effectChannel.close()
        super.onCleared()
    }
}

