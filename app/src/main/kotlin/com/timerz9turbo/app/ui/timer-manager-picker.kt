package com.timerz9turbo.app.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.timerz9turbo.app.R
import androidx.core.graphics.drawable.toBitmap
import com.timerz9turbo.app.data.ManagerScanner
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.overlay.OverlayBottomSheet
import top.yukonga.miuix.kmp.theme.MiuixTheme

@Composable
internal fun TimerManagerPickerSheet(
    state: TimerUiState,
    actions: TimerActions,
) {
    OverlayBottomSheet(
        show = state.managerPickerVisible,
        title = stringResource(R.string.manager_select),
        onDismissRequest = actions::onCloseManagerPicker,
        content = {
            var showAll by remember { mutableStateOf(false) }
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 480.dp)
                    .navigationBarsPadding()
                    .selectableGroup(),
            ) {
                if (state.managerCandidates.isEmpty()) {
                    item {
                        Text(
                            text = stringResource(R.string.manager_picker_empty),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 24.dp),
                            textAlign = TextAlign.Center,
                            color = MiuixTheme.colorScheme.onBackgroundVariant,
                        )
                    }
                } else {
                    val compatible = state.managerCandidates.filter { it.hasKsud }
                    val incompatible = state.managerCandidates.filterNot { it.hasKsud }
                    val visibleIncompatible = if (showAll) incompatible else emptyList()
                    items(compatible, key = { it.packageName }) { candidate ->
                        ManagerPickerRow(
                            title = candidate.label,
                            subtitle = candidate.packageName,
                            icon = candidate,
                            selected = state.selectedManagerPackage == candidate.packageName,
                        ) { actions.onManagerSelected(candidate.packageName) }
                    }
                    items(visibleIncompatible, key = { it.packageName }) { candidate ->
                        ManagerPickerRow(
                            title = candidate.label,
                            subtitle = stringResource(R.string.manager_no_ksud),
                            icon = candidate,
                            selected = state.selectedManagerPackage == candidate.packageName,
                            muted = true,
                        ) { actions.onManagerSelected(candidate.packageName) }
                    }
                    if (incompatible.isNotEmpty()) {
                        item {
                            TextButton(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(top = 8.dp, bottom = 4.dp),
                                text = stringResource(
                                    if (showAll) R.string.manager_hide_all else R.string.manager_show_all,
                                ),
                                onClick = { showAll = !showAll },
                            )
                        }
                    }
                }
            }
        },
    )
}

@Composable
private fun ManagerPickerRow(
    title: String,
    subtitle: String?,
    icon: ManagerScanner.Candidate?,
    selected: Boolean,
    muted: Boolean = false,
    onClick: () -> Unit,
) {
    val context = LocalContext.current
    val pm = context.packageManager
    val imageBitmap = remember(icon) {
        icon?.let { candidate ->
            runCatching {
                val drawable = pm.getApplicationIcon(candidate.packageName)
                val width = maxOf(drawable.intrinsicWidth, 1)
                val height = maxOf(drawable.intrinsicHeight, 1)
                drawable.toBitmap(width, height)
            }.getOrNull()
        }?.asImageBitmap()
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(
                selected = selected,
                role = Role.RadioButton,
                onClick = onClick,
            )
            .padding(horizontal = 24.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (imageBitmap != null) {
            Image(
                bitmap = imageBitmap,
                contentDescription = null,
                modifier = Modifier
                    .size(40.dp)
                    .padding(end = 0.dp),
            )
            Spacer(Modifier.width(12.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(
                text = title,
                color = if (muted) MiuixTheme.colorScheme.onBackgroundVariant else MiuixTheme.colorScheme.onBackground,
            )
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MiuixTheme.textStyles.footnote1,
                    color = MiuixTheme.colorScheme.onBackgroundVariant,
                )
            }
        }
        if (selected) {
            Spacer(Modifier.width(8.dp))
            Icon(
                imageVector = Icons.Rounded.CheckCircleOutline,
                contentDescription = null,
                tint = MiuixTheme.colorScheme.primary,
            )
        }
    }
}
