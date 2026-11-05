package com.timerz9turbo.app.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import top.yukonga.miuix.kmp.nav.core.navBackStackOf

class TimerNavigationTest {
    @Test
    fun `only main advanced and about participate in navigation`() {
        assertEquals(listOf(TimerScreen.Main), navigationPath(TimerUiState()))
        assertEquals(listOf(TimerScreen.Main, TimerScreen.Advanced), navigationPath(TimerUiState(advancedScreenVisible = true)))
        assertEquals(listOf(TimerScreen.Main, TimerScreen.Advanced, TimerScreen.About),
            navigationPath(TimerUiState(advancedScreenVisible = true, aboutVisible = true)))
        assertEquals(listOf(TimerScreen.Main), navigationPath(TimerUiState(aboutVisible = true)))
    }

    @Test
    fun `closing advanced removes its nested about entry`() {
        val stack = navBackStackOf(TimerScreen.Main, TimerScreen.Advanced, TimerScreen.About)
        syncNavigationPath(stack, navigationPath(TimerUiState()))
        assertEquals(listOf(TimerScreen.Main), stack.toList())
    }
}
