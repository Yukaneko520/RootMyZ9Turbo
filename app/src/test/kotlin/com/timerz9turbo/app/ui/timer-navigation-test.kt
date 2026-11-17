package com.timerz9turbo.app.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import top.yukonga.miuix.kmp.nav.core.navBackStackOf

class TimerNavigationTest {
    @Test
    fun `only main advanced adb root and about participate in navigation`() {
        assertEquals(listOf(TimerScreen.Main), navigationPath(TimerUiState()))
        assertEquals(listOf(TimerScreen.Main, TimerScreen.Advanced), navigationPath(TimerUiState(advancedScreenVisible = true)))
        assertEquals(listOf(TimerScreen.Main, TimerScreen.Advanced, TimerScreen.AdbRoot),
            navigationPath(TimerUiState(advancedScreenVisible = true, adbRootScreenVisible = true)))
        assertEquals(listOf(TimerScreen.Main, TimerScreen.Advanced, TimerScreen.About),
            navigationPath(TimerUiState(advancedScreenVisible = true, aboutVisible = true)))
        assertEquals(listOf(TimerScreen.Main), navigationPath(TimerUiState(aboutVisible = true)))
        // The status banner opens the ADB setup without the Advanced screen.
        assertEquals(listOf(TimerScreen.Main, TimerScreen.AdbRoot),
            navigationPath(TimerUiState(adbRootScreenVisible = true)))
    }

    @Test
    fun `closing advanced removes its nested screens`() {
        val stack = navBackStackOf(TimerScreen.Main, TimerScreen.Advanced, TimerScreen.About)
        syncNavigationPath(stack, navigationPath(TimerUiState()))
        assertEquals(listOf(TimerScreen.Main), stack.toList())
    }
}
