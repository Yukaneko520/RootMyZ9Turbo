package com.timerz9turbo.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.nav.core.NavBackStack
import top.yukonga.miuix.kmp.nav.core.NavDisplay
import top.yukonga.miuix.kmp.nav.core.NavDisplayEffects
import top.yukonga.miuix.kmp.nav.core.NavKey
import top.yukonga.miuix.kmp.nav.core.navBackStackOf
import top.yukonga.miuix.kmp.nav.core.rememberNavSystemCornerRadius
import top.yukonga.miuix.kmp.nav.transition.NavSwipeDirection
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.darkColorScheme
import top.yukonga.miuix.kmp.theme.lightColorScheme

internal sealed interface TimerScreen : NavKey {
    data object Main : TimerScreen
    data object Advanced : TimerScreen
    data object About : TimerScreen
}

internal fun navigationPath(state: TimerUiState): List<TimerScreen> = buildList {
    add(TimerScreen.Main)
    if (state.advancedScreenVisible) {
        add(TimerScreen.Advanced)
        if (state.aboutVisible) add(TimerScreen.About)
    }
}

internal fun syncNavigationPath(backStack: NavBackStack, desired: List<TimerScreen>) {
    var common = 0
    while (common < backStack.size && common < desired.size &&
        backStack[common] == desired[common]
    ) {
        common++
    }
    while (backStack.size > common) backStack.removeAt(backStack.lastIndex)
    backStack.addAll(desired.drop(common))
}

private fun closeScreen(screen: TimerScreen, actions: TimerActions) {
    when (screen) {
        TimerScreen.Main -> Unit
        TimerScreen.Advanced -> actions.onCloseAdvanced()
        TimerScreen.About -> actions.onCloseAbout()
    }
}

@Composable
internal fun TimerApp(
    state: TimerUiState,
    actions: TimerActions,
) {
    MiuixTheme(
        colors = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme(),
    ) {
        val desiredPath = navigationPath(state)
        val backStack = remember {
            navBackStackOf(TimerScreen.Main).apply { addAll(desiredPath.drop(1)) }
        }
        LaunchedEffect(desiredPath) { syncNavigationPath(backStack, desiredPath) }
        val swipeBack = if (LocalLayoutDirection.current == LayoutDirection.Rtl) {
            NavSwipeDirection.RightToLeft
        } else {
            NavSwipeDirection.LeftToRight
        }
        Scaffold(modifier = Modifier.fillMaxSize()) { _ ->
            Box(modifier = Modifier.fillMaxSize()) {
                NavDisplay(
                    backStack = backStack,
                    modifier = Modifier.fillMaxSize(),
                    effects = NavDisplayEffects(cornerClipRadius = rememberNavSystemCornerRadius()),
                    onBack = {
                        when {
                            state.executionSheetVisible -> {
                                if (state.executionSheetDismissible) actions.onCloseExecutionSheet()
                            }
                            else -> {
                                val screen = backStack.lastOrNull() as? TimerScreen
                                if (screen != null && screen != TimerScreen.Main) {
                                    closeScreen(screen, actions)
                                    backStack.removeAt(backStack.lastIndex)
                                }
                            }
                        }
                    },
                ) {
                    entry<TimerScreen.Main>(swipeDismiss = NavSwipeDirection.None) {
                        MainScreen(state = state, actions = actions)
                    }
                    entry<TimerScreen.Advanced>(swipeDismiss = swipeBack) {
                        AdvancedScreen(state = state, actions = actions)
                    }
                    entry<TimerScreen.About>(swipeDismiss = swipeBack) {
                        AboutScreen(onBack = actions::onCloseAbout)
                    }
                }
                TimerExecutionSheet(state = state, actions = actions)
                TimerManagerPickerSheet(state = state, actions = actions)
            }
        }
    }
}

@Composable
internal fun pageContentPadding(
    scaffoldPadding: PaddingValues,
    top: Dp = 8.dp,
    bottom: Dp = 12.dp,
    horizontalMin: Dp = 12.dp,
): PaddingValues {
    val windowWidth = with(LocalDensity.current) {
        LocalWindowInfo.current.containerSize.width.toDp()
    }
    val horizontal = ((windowWidth - 800.dp) / 2).coerceAtLeast(horizontalMin)
    return PaddingValues(
        start = horizontal,
        end = horizontal,
        top = scaffoldPadding.calculateTopPadding() + top,
        bottom = scaffoldPadding.calculateBottomPadding() + bottom,
    )
}
