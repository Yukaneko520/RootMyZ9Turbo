package com.timerz9turbo.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircleOutline
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.RemoveCircleOutline
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.timerz9turbo.app.R
import com.timerz9turbo.app.domain.model.ShizukuStatus
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.utils.PressFeedbackType

@Composable
internal fun ActivationStatusCard(
    supported: Boolean,
    shizukuStatus: ShizukuStatus,
    onShizukuClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val accessReady = shizukuStatus == ShizukuStatus.READY
    val ready = supported && accessReady
    val missing = !supported
    val (backgroundColor, title, icon) = when {
        ready -> Triple(
            when {
                MiuixTheme.isDynamicColor -> MiuixTheme.colorScheme.secondaryContainer
                isSystemInDarkTheme() -> Color(0xFF1A3825)
                else -> Color(0xFFDFFAE4)
            },
            R.string.kernel_supported,
            Icons.Rounded.CheckCircleOutline,
        )

        missing -> Triple(
            MiuixTheme.colorScheme.errorContainer,
            R.string.kernel_unsupported,
            Icons.Rounded.RemoveCircleOutline,
        )

        else -> Triple(
            when {
                MiuixTheme.isDynamicColor -> MiuixTheme.colorScheme.tertiaryContainer
                isSystemInDarkTheme() -> Color(0xFF3E2F1B)
                else -> Color(0xFFFFF0DB)
            },
            R.string.shizuku_label,
            Icons.Rounded.ErrorOutline,
        )
    }
    val summary = when {
        ready -> R.string.shizuku_status_ready
        !supported -> R.string.kernel_unsupported_summary
        shizukuStatus == ShizukuStatus.PERMISSION_REQUIRED -> R.string.shizuku_status_permission_required
        else -> R.string.shizuku_status_not_running
    }
    // Tap re-runs the Shizuku flow (open app / request permission); no-op when READY.
    Card(
        modifier = modifier,
        colors = CardDefaults.defaultColors(color = backgroundColor),
        onClick = onShizukuClick,
        showIndication = true,
        pressFeedbackType = PressFeedbackType.Tilt,
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 110.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (MiuixTheme.isDynamicColor) {
                    when (icon) {
                        Icons.Rounded.CheckCircleOutline -> MiuixTheme.colorScheme.primary.copy(alpha = 0.8f)
                        Icons.Rounded.RemoveCircleOutline ->
                            MiuixTheme.colorScheme.onTertiaryContainer.copy(alpha = 0.8f)

                        else -> MiuixTheme.colorScheme.onErrorContainer.copy(alpha = 0.8f)
                    }
                } else {
                    when (icon) {
                        Icons.Rounded.CheckCircleOutline -> Color(0xFF36D167)
                        Icons.Rounded.RemoveCircleOutline -> Color(0xFFF5A623)
                        else -> Color(0xFFF72727)
                    }
                },
                modifier = Modifier
                    .align(Alignment.BottomEnd)
                    .offset(x = 27.dp, y = 31.dp)
                    .size(110.dp),
            )
            Column(
                modifier = Modifier.padding(start = 16.dp, top = 14.dp, end = 120.dp, bottom = 14.dp),
            ) {
                Text(
                    text = stringResource(title),
                    fontSize = 22.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(modifier = Modifier.height(1.dp))
                Text(
                    text = stringResource(summary),
                    fontSize = 15.sp,
                )
            }
        }
    }
}

@Composable
internal fun DeviceInfoCard(
    deviceName: String,
    socName: String,
    kernelRelease: String,
    androidVersion: String,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier,
        insideMargin = PaddingValues(16.dp),
    ) {
        SelectionContainer {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                DeviceInfoItem(
                    title = stringResource(R.string.device_label),
                    value = deviceName,
                )
                DeviceInfoItem(
                    title = stringResource(R.string.soc_label),
                    value = socName,
                )
                DeviceInfoItem(
                    title = stringResource(R.string.kernel_label),
                    value = kernelRelease,
                )
                DeviceInfoItem(
                    title = stringResource(R.string.android_label),
                    value = androidVersion,
                )
            }
        }
    }
}

@Composable
private fun DeviceInfoItem(
    title: String,
    value: String,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        Text(
            text = title,
            fontSize = 18.sp,
            fontWeight = FontWeight.Medium,
            color = MiuixTheme.colorScheme.onSurface,
        )
        Text(
            text = value,
            modifier = Modifier.padding(top = 2.dp),
            fontSize = 14.sp,
            color = MiuixTheme.colorScheme.onSurface.copy(alpha = 0.68f),
        )
    }
}
