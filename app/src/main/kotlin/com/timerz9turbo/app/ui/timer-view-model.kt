package com.timerz9turbo.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.timerz9turbo.app.R
import com.timerz9turbo.app.data.TimerRepository
import com.timerz9turbo.app.domain.model.AdbLinkStatus
import com.timerz9turbo.app.domain.model.SetupActionResult
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
            val adbSettings = repository.adbSettings()
            val adbStatus = repository.adbLinkStatus()
            val adbSnap = if (mutableState.value.adbRootScreenVisible) {
                runCatching { repository.adbRefreshSetup() }.getOrNull()
            } else {
                null
            }
            mutableState.update { it.copy(
                deviceName = snapshot.deviceName, kernelRelease = snapshot.kernelRelease,
                socName = snapshot.socName, androidVersion = snapshot.androidVersion,
                kernelSupported = snapshot.kernelSupported, safeModeEnabled = snapshot.safeModeEnabled,
                shizukuStatus = snapshot.shizukuStatus, selectedManagerPackage = repository.selectedManagerPackage(),
                debugExportEnabled = settings.exportEnabled, debugExportLocation = settings.exportLocation,
                kernelOnlyMatchEnabled = repository.kernelOnlyMatchEnabled(),
                adbSettings = adbSettings,
                adbLinkStatus = adbSnap?.linkStatus ?: adbStatus,
                adbSnapshot = adbSnap ?: it.adbSnapshot,
                uptimeCooldownSeconds = repository.uptimeCooldownSeconds(),
            ) }
        }
    }

    override fun onStatusClick() {
        if (state.value.adbSettings.manualEnabled) return
        when (state.value.shizukuStatus) {
            ShizukuStatus.NOT_RUNNING -> send(TimerEffect.OpenShizuku)
            ShizukuStatus.PERMISSION_REQUIRED -> repository.requestShizukuPermission()
            ShizukuStatus.READY -> Unit
        }
    }

    override fun onRunBlocked() {
        if (state.value.adbSettings.manualEnabled) {
            if (state.value.adbLinkStatus != AdbLinkStatus.READY) {
                send(TimerEffect.Toast(R.string.adb_not_ready))
                refreshAccessStatus()
            }
            return
        }
        onStatusClick()
    }

    override fun onRun() = run(diagnose = false)
    override fun onRunDiagnose() = run(diagnose = true)

    private fun run(diagnose: Boolean) {
        val current = state.value
        if (current.running) return
        if (!diagnose && !current.kernelSupported) return
        val adbMode = current.adbSettings.manualEnabled
        if (adbMode) {
            if (current.adbLinkStatus != AdbLinkStatus.READY) {
                send(TimerEffect.Toast(R.string.adb_not_ready))
                refreshAccessStatus()
                return
            }
            if (!diagnose && current.selectedManagerPackage.isNullOrBlank()) {
                send(TimerEffect.Toast(R.string.manager_select))
                return
            }
        } else {
            if (current.shizukuStatus != ShizukuStatus.READY) { onStatusClick(); return }
            if (!diagnose && current.selectedManagerPackage.isNullOrBlank()) {
                send(TimerEffect.Toast(R.string.manager_select))
                return
            }
        }
        mutableState.update { it.copy(running = true, executionSheetVisible = true, executionSheetDismissible = false) }
        send(TimerEffect.KeepScreenAwake(true))
        when {
            diagnose -> appendLog("==== diagnose (timer ids, no UAF) ====")
            adbMode -> {
                appendLog("==== start Timer/ADB ====")
                send(TimerEffect.Toast(R.string.adb_root_started))
            }
            else -> appendLog("==== start Timer/Shizuku ====")
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val code = if (adbMode) {
                    repository.runAdb(diagnose, current.safeModeEnabled, ::appendLog)
                } else {
                    repository.run(diagnose, ::appendLog)
                }
                appendLog(if (code == 0) "result: completed" else "result: failed (exit code=$code)")
                if (adbMode && !diagnose) {
                    send(TimerEffect.Toast(if (code == 0) R.string.adb_root_success else R.string.adb_root_failed))
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                appendLog("result: failed (${error.message})")
                if (adbMode && !diagnose) send(TimerEffect.Toast(R.string.adb_root_failed))
            } finally {
                mutableState.update { it.copy(running = false, executionSheetDismissible = true) }
                send(TimerEffect.KeepScreenAwake(false))
                refreshAccessStatus()
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

    override fun onOpenUptimeCooldownPicker() {
        mutableState.update { it.copy(uptimeCooldownPickerVisible = true) }
    }

    override fun onCloseUptimeCooldownPicker() {
        mutableState.update { it.copy(uptimeCooldownPickerVisible = false) }
    }

    override fun onUptimeCooldownSelected(seconds: Int) {
        repository.setUptimeCooldownSeconds(seconds)
        mutableState.update { it.copy(uptimeCooldownSeconds = seconds, uptimeCooldownPickerVisible = false) }
    }

    override fun onOpenManagerPicker() {
        if (state.value.managerLoading) {
            mutableState.update { it.copy(managerPickerVisible = true) }
            return
        }
        mutableState.update { it.copy(managerPickerVisible = true, managerLoading = true, managerLoadFailed = false) }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val managers = repository.installedManagers()
                mutableState.update { it.copy(managerCandidates = managers) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                mutableState.update { it.copy(managerLoadFailed = true) }
                appendLog("<k> error: cannot scan managers: ${error.message}")
            } finally {
                mutableState.update { it.copy(managerLoading = false) }
            }
        }
    }

    override fun onCloseManagerPicker() { mutableState.update { it.copy(managerPickerVisible = false) } }
    override fun onManagerSelected(pkg: String?) {
        repository.setSelectedManagerPackage(pkg)
        mutableState.update { it.copy(selectedManagerPackage = pkg, managerPickerVisible = false) }
    }
    override fun onOpenAdvanced() { mutableState.update { it.copy(advancedScreenVisible = true) } }
    override fun onCloseAdvanced() {
        mutableState.update { it.copy(advancedScreenVisible = false, aboutVisible = false, adbRootScreenVisible = false) }
    }
    override fun onShowAbout() { mutableState.update { it.copy(aboutVisible = true, adbRootScreenVisible = false) } }
    override fun onCloseAbout() { mutableState.update { it.copy(aboutVisible = false) } }
    override fun onDebugExportChanged(enabled: Boolean) {
        repository.setDebugExportEnabled(enabled)
        mutableState.update { it.copy(debugExportEnabled = enabled) }
    }
    override fun onDebugExportLocationPick() = send(TimerEffect.PickDebugFolder)
    override fun onKernelOnlyMatchChanged(enabled: Boolean) {
        repository.setKernelOnlyMatchEnabled(enabled)
        refreshAccessStatus()
    }
    fun onDebugExportLocationPicked(location: String?, treeUri: String? = null) {
        if (location == null) { send(TimerEffect.Toast(R.string.debug_export_location_unsupported)); return }
        if (runCatching { repository.setDebugExportLocation(location, treeUri) }.isFailure) {
            send(TimerEffect.Toast(R.string.debug_export_location_unsupported))
            return
        }
        mutableState.update { it.copy(debugExportLocation = repository.debugSettings().exportLocation) }
    }

    override fun onAdbStatusClick() = openAdbRoot(fromAdvanced = false)

    override fun onOpenAdbRoot() = openAdbRoot(fromAdvanced = true)

    private fun openAdbRoot(fromAdvanced: Boolean) {
        mutableState.update {
            it.copy(
                advancedScreenVisible = fromAdvanced,
                adbRootScreenVisible = true,
                aboutVisible = false,
                adbBusy = true,
                adbSettings = repository.adbSettings(),
            )
        }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val local = repository.adbLocalSnapshot()
                mutableState.update { it.copy(adbSnapshot = local) }
                val snapshot = repository.adbRefreshSetup()
                mutableState.update {
                    it.copy(
                        adbSnapshot = snapshot,
                        adbSettings = repository.adbSettings(),
                        adbBusy = false,
                        adbLinkStatus = snapshot.linkStatus,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                mutableState.update { it.copy(adbBusy = false) }
                send(TimerEffect.ToastText(error.message.orEmpty().ifBlank { "ADB setup failed" }))
            }
        }
    }

    override fun onCloseAdbRoot() {
        mutableState.update { it.copy(adbRootScreenVisible = false) }
    }

    private fun refreshAdbSetup(toastResult: Boolean = false) {
        if (state.value.adbBusy) return
        mutableState.update { it.copy(adbBusy = true) }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val snapshot = repository.adbRefreshSetup()
                mutableState.update {
                    it.copy(
                        adbSnapshot = snapshot,
                        adbSettings = repository.adbSettings(),
                        adbBusy = false,
                        adbLinkStatus = snapshot.linkStatus,
                    )
                }
                if (toastResult) {
                    if (snapshot.setupComplete) {
                        send(TimerEffect.Toast(R.string.adb_setup_complete))
                    } else {
                        send(TimerEffect.Toast(R.string.adb_setup_incomplete))
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                mutableState.update { it.copy(adbBusy = false) }
                send(TimerEffect.ToastText(error.message.orEmpty().ifBlank { "ADB setup failed" }))
            }
        }
    }

    private fun runAdbSetupAction(
        successToast: Int? = null,
        action: suspend () -> SetupActionResult,
    ) {
        if (state.value.adbBusy) return
        mutableState.update { it.copy(adbBusy = true) }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val result = action()
                if (!result.ok) {
                    if (result.detail.isBlank()) send(TimerEffect.Toast(R.string.adb_action_failed))
                    else send(TimerEffect.ToastText(result.detail))
                } else if (successToast != null) {
                    send(TimerEffect.Toast(successToast))
                }
                val refreshed = repository.adbRefreshSetup()
                mutableState.update {
                    it.copy(
                        adbSnapshot = refreshed,
                        adbSettings = repository.adbSettings(),
                        adbBusy = false,
                        adbLinkStatus = refreshed.linkStatus,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                mutableState.update { it.copy(adbBusy = false) }
                send(TimerEffect.ToastText(error.message.orEmpty().ifBlank { "ADB setup failed" }))
            }
        }
    }

    override fun onAdbApplyPort() = runAdbSetupAction { repository.adbApplyPersistPort() }

    override fun onAdbInstallKey() = runAdbSetupAction(
        successToast = R.string.adb_key_authorized,
    ) { repository.adbInstallKey() }

    override fun onAdbResetSetup() {
        if (state.value.adbBusy) return
        mutableState.update { it.copy(adbBusy = true) }
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val result = repository.adbResetSetup()
                val refreshed = repository.adbRefreshSetup()
                mutableState.update {
                    it.copy(
                        adbSnapshot = refreshed,
                        adbSettings = repository.adbSettings(),
                        adbBusy = false,
                        adbLinkStatus = refreshed.linkStatus,
                    )
                }
                if (result.ok) {
                    send(TimerEffect.Toast(R.string.adb_reset_setup_success))
                } else {
                    val detail = result.detail.trim()
                    if (detail.isBlank()) send(TimerEffect.ToastFormatted(R.string.adb_reset_setup_failed, "failed"))
                    else send(TimerEffect.ToastFormatted(R.string.adb_reset_setup_failed, detail))
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                mutableState.update { it.copy(adbBusy = false) }
                send(TimerEffect.ToastFormatted(R.string.adb_reset_setup_failed, error.message.orEmpty()))
            }
        }
    }

    override fun onAdbManualChanged(enabled: Boolean) {
        repository.setAdbManualEnabled(enabled)
        mutableState.update { it.copy(adbSettings = repository.adbSettings()) }
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
