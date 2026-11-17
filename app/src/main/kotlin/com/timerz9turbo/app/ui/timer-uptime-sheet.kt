package com.timerz9turbo.app.ui

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.timerz9turbo.app.R
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.overlay.OverlayBottomSheet
import top.yukonga.miuix.kmp.theme.MiuixTheme

internal val UPTIME_COOLDOWN_OPTIONS = listOf(0, 5, 10, 15, 20, 30, 45, 60, 90, 120)

@Composable
internal fun TimerUptimeCooldownPickerSheet(
    state: TimerUiState,
    actions: TimerActions,
) {
    OverlayBottomSheet(
        show = state.uptimeCooldownPickerVisible,
        title = stringResource(R.string.uptime_cooldown_title),
        onDismissRequest = actions::onCloseUptimeCooldownPicker,
        content = {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 480.dp)
                    .navigationBarsPadding()
                    .selectableGroup(),
            ) {
                items(UPTIME_COOLDOWN_OPTIONS) { seconds ->
                    val label = when (seconds) {
                        0 -> stringResource(R.string.uptime_cooldown_none)
                        60 -> stringResource(R.string.uptime_cooldown_60s_default)
                        else -> stringResource(R.string.uptime_cooldown_seconds, seconds)
                    }
                    UptimeCooldownRow(
                        label = label,
                        selected = state.uptimeCooldownSeconds == seconds,
                        onClick = { actions.onUptimeCooldownSelected(seconds) },
                    )
                }
            }
        },
    )
}

@Composable
private fun UptimeCooldownRow(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(
                selected = selected,
                role = Role.RadioButton,
                onClick = onClick,
            )
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            fontSize = 16.sp,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            color = if (selected) MiuixTheme.colorScheme.primary else MiuixTheme.colorScheme.onBackground,
            modifier = Modifier.weight(1f),
        )
        if (selected) {
            Icon(
                imageVector = Icons.Rounded.CheckCircleOutline,
                contentDescription = null,
                tint = MiuixTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp),
            )
        }
    }
}
