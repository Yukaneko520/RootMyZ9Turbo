package com.timerz9turbo.app.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.material.icons.rounded.WarningAmber
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.timerz9turbo.app.R
import com.timerz9turbo.app.domain.model.AdbLinkStatus
import com.timerz9turbo.app.domain.model.AdbSetupCheck
import com.timerz9turbo.app.domain.model.AdbSetupSnapshot
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.overlay.OverlayDialog
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
internal fun AdbRootScreen(
    state: TimerUiState,
    actions: TimerActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.adb_root_settings),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = actions::onCloseAdbRoot) {
                        Icon(
                            imageVector = MiuixIcons.Back,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = pageContentPadding(paddingValues),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "checklist") {
                SetupChecklistCard(state = state, actions = actions)
            }
            item(key = "options") {
                Card {
                    SwitchPreference(
                        checked = state.adbSettings.manualEnabled,
                        onCheckedChange = actions::onAdbManualChanged,
                        title = stringResource(R.string.adb_manual_switch),
                        summary = stringResource(R.string.adb_manual_switch_summary),
                    )
                }
            }
            item(key = "warnings") {
                AdbNotesCard(state = state)
            }
            item(key = "reset_adb") {
                TextButton(
                    text = stringResource(R.string.adb_reset_setup),
                    enabled = !state.adbBusy && !state.running,
                    onClick = actions::onAdbResetSetup,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

@Composable
private fun SetupChecklistCard(
    state: TimerUiState,
    actions: TimerActions,
) {
    val context = LocalContext.current
    val snapshot = state.adbSnapshot
    val showPortWarningDialog = remember { mutableStateOf(false) }

    val portCheck = when {
        snapshot.persistPort == null -> AdbSetupCheck.UNKNOWN
        snapshot.portOk -> AdbSetupCheck.OK
        else -> AdbSetupCheck.FAIL
    }
    val keyCheck = when {
        snapshot.keyFingerprint == null -> AdbSetupCheck.UNKNOWN
        snapshot.keyOk -> AdbSetupCheck.OK
        else -> AdbSetupCheck.FAIL
    }
    val allowedCheck = when {
        snapshot.allowedTimeOk -> AdbSetupCheck.OK
        snapshot.allowedConnectionTime == null -> AdbSetupCheck.WARN
        else -> AdbSetupCheck.WARN
    }

    if (showPortWarningDialog.value) {
        OverlayDialog(
            show = showPortWarningDialog.value,
            title = stringResource(R.string.adb_port_warning_title),
            summary = stringResource(R.string.adb_port_warning_message),
            onDismissRequest = { showPortWarningDialog.value = false },
            content = {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    TextButton(
                        text = stringResource(R.string.adb_port_warning_cancel),
                        onClick = { showPortWarningDialog.value = false },
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        text = stringResource(R.string.adb_port_warning_confirm),
                        colors = ButtonDefaults.textButtonColorsPrimary(),
                        onClick = {
                            showPortWarningDialog.value = false
                            actions.onAdbApplyPort()
                        },
                        modifier = Modifier.weight(1f),
                    )
                }
            },
        )
    }

    Card {
        Column(modifier = Modifier.padding(vertical = 6.dp)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.adb_setup_checklist),
                    modifier = Modifier.weight(1f),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = stringResource(
                        if (snapshot.setupComplete) R.string.adb_setup_complete else R.string.adb_setup_incomplete,
                    ),
                    fontSize = 13.sp,
                    color = if (snapshot.setupComplete) {
                        MiuixTheme.colorScheme.primary
                    } else {
                        MiuixTheme.colorScheme.onBackgroundVariant
                    },
                )
            }
            SetupCheckRow(
                title = stringResource(R.string.adb_setup_check_port),
                summary = portSummary(snapshot),
                check = portCheck,
                actionLabel = stringResource(R.string.adb_port_action),
                busy = state.adbBusy,
                onAction = { showPortWarningDialog.value = true },
            )
            SetupCheckRow(
                title = stringResource(R.string.adb_setup_check_key),
                summary = keySummary(snapshot),
                check = keyCheck,
                actionLabel = stringResource(
                    when {
                        snapshot.keyOk -> R.string.adb_key_done
                        snapshot.keyRejected || snapshot.linkStatus == AdbLinkStatus.UNAUTHORIZED -> R.string.adb_key_retry
                        else -> R.string.adb_key_action
                    }
                ),
                busy = state.adbBusy,
                enabled = !state.adbBusy && !snapshot.keyOk,
                onAction = actions::onAdbInstallKey,
            )
            SetupCheckRow(
                title = stringResource(R.string.adb_setup_check_allowed),
                summary = if (snapshot.allowedTimeOk) {
                    stringResource(R.string.adb_allowed_ok)
                } else {
                    stringResource(R.string.adb_allowed_summary)
                },
                check = allowedCheck,
                actionLabel = stringResource(R.string.adb_allowed_action),
                busy = false,
                enabled = true,
                onAction = { openDevSettingsHighlightTimeout(context) },
            )
            if (state.adbBusy) {
                Text(
                    text = stringResource(R.string.adb_busy),
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.onBackgroundVariant,
                )
            }
        }
    }
}

@Composable
private fun SetupCheckRow(
    title: String,
    summary: String,
    check: AdbSetupCheck,
    actionLabel: String,
    busy: Boolean,
    enabled: Boolean = !busy,
    onAction: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 16.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = when (check) {
                AdbSetupCheck.OK -> Icons.Rounded.CheckCircleOutline
                AdbSetupCheck.FAIL -> Icons.Rounded.ErrorOutline
                AdbSetupCheck.WARN -> Icons.Rounded.WarningAmber
                AdbSetupCheck.UNKNOWN -> Icons.Rounded.RemoveCircleOutline
            },
            contentDescription = null,
            tint = checkColor(check),
            modifier = Modifier.size(22.dp),
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, fontSize = 16.sp, fontWeight = FontWeight.Medium)
            Text(
                text = summary,
                fontSize = 13.sp,
                color = MiuixTheme.colorScheme.onBackgroundVariant,
            )
        }
        Spacer(modifier = Modifier.width(8.dp))
        TextButton(
            text = actionLabel,
            enabled = enabled,
            onClick = onAction,
        )
    }
}

@Composable
private fun checkColor(check: AdbSetupCheck): Color = when (check) {
    AdbSetupCheck.OK -> MiuixTheme.colorScheme.primary
    AdbSetupCheck.FAIL -> MiuixTheme.colorScheme.error
    AdbSetupCheck.WARN -> Color(0xFFF5A623)
    AdbSetupCheck.UNKNOWN -> MiuixTheme.colorScheme.onBackgroundVariant
}

@Composable
private fun AdbNotesCard(state: TimerUiState) {
    Card {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            state.adbSnapshot.error?.takeIf { it.isNotBlank() }?.let { error ->
                Text(
                    text = error,
                    fontSize = 13.sp,
                    color = MiuixTheme.colorScheme.error,
                )
            }
            if (!state.adbSnapshot.allowedTimeOk) {
                Text(
                    text = stringResource(R.string.adb_allowed_warning),
                    fontSize = 13.sp,
                    color = Color(0xFFF5A623),
                )
            }
            Text(
                text = stringResource(R.string.adb_note),
                fontSize = 13.sp,
                color = MiuixTheme.colorScheme.onBackgroundVariant,
            )
        }
    }
}

@Composable
private fun portSummary(snapshot: AdbSetupSnapshot): String {
    val port = when {
        snapshot.persistPort == null -> stringResource(R.string.adb_port_unknown)
        snapshot.portOk -> stringResource(R.string.adb_port_ok)
        else -> stringResource(R.string.adb_port_missing, snapshot.persistPort.ifEmpty { "(empty)" })
    }
    val service = snapshot.servicePort?.let {
        stringResource(R.string.adb_service_port, it.ifEmpty { "(empty)" })
    }
    return if (service == null) port else "$port\n$service"
}

@Composable
private fun fingerprintDisplay(snapshot: AdbSetupSnapshot): String {
    val md5 = snapshot.keyFingerprint ?: return ""
    val sha256 = snapshot.keyFingerprintSha256
    return if (sha256 != null) {
        stringResource(R.string.adb_key_fingerprint, md5, sha256)
    } else {
        stringResource(R.string.adb_key_fingerprint_md5, md5)
    }
}

@Composable
private fun keySummary(snapshot: AdbSetupSnapshot): String = when {
    snapshot.keyFingerprint == null -> stringResource(R.string.adb_key_missing)
    snapshot.keyOk -> stringResource(R.string.adb_key_installed) + "\n" +
        fingerprintDisplay(snapshot)

    snapshot.keyRejected || snapshot.linkStatus == AdbLinkStatus.UNAUTHORIZED ->
        stringResource(R.string.adb_key_rejected) + "\n" +
            fingerprintDisplay(snapshot)

    else -> stringResource(R.string.adb_key_not_installed) + "\n" +
        fingerprintDisplay(snapshot)
}

private fun openDevSettingsHighlightTimeout(context: Context) {
    val key = "adb_authorization_timeout"
    val fragmentArgs = Bundle().apply {
        putString(":settings:fragment_args_key", key)
    }
    val intent = Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        putExtra(":settings:fragment_args_key", key)
        putExtra(":settings:show_fragment_args", fragmentArgs)
        putExtra("android.provider.extra.SETTINGS_EMBEDDED_DEEP_LINK_HIGHLIGHT_MENU_KEY", key)
    }
    runCatching {
        context.startActivity(intent)
    }.onFailure {
        runCatching {
            context.startActivity(
                Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }
    }
}
