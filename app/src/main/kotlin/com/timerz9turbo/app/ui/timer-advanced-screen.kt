package com.timerz9turbo.app.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.timerz9turbo.app.R
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberTopAppBarState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
internal fun AdvancedScreen(
    state: TimerUiState,
    actions: TimerActions,
) {
    val scrollBehavior = MiuixScrollBehavior(rememberTopAppBarState())
    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.advanced_settings),
                scrollBehavior = scrollBehavior,
                navigationIcon = {
                    IconButton(onClick = actions::onCloseAdvanced) {
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
                .imePadding()
                .scrollEndHaptic()
                .overScrollVertical()
                .nestedScroll(scrollBehavior.nestedScrollConnection),
            contentPadding = pageContentPadding(paddingValues),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item(key = "diagnose") {
                Card {
                    ArrowPreference(
                        title = stringResource(R.string.diagnose),
                        summary = stringResource(R.string.diagnose_summary),
                        onClick = actions::onRunDiagnose,
                    )
                }
            }
            item(key = "export") {
                Card {
                    Column {
                        SwitchPreference(
                            checked = state.debugExportEnabled,
                            onCheckedChange = actions::onDebugExportChanged,
                            title = stringResource(R.string.debug_export_log),
                            summary = stringResource(R.string.debug_export_log_summary),
                        )
                        AnimatedVisibility(
                            visible = state.debugExportEnabled,
                            enter = expandVertically(),
                            exit = shrinkVertically(),
                        ) {
                            Column {
                                ArrowPreference(
                                    title = stringResource(R.string.debug_export_location),
                                    summary = state.debugExportLocation,
                                    onClick = actions::onDebugExportLocationPick,
                                )
                            }
                        }
                    }
                }
            }
            item(key = "about") {
                Card {
                    ArrowPreference(
                        title = stringResource(R.string.about),
                        summary = stringResource(R.string.about_summary),
                        onClick = actions::onShowAbout,
                    )
                }
            }
        }
    }
}
