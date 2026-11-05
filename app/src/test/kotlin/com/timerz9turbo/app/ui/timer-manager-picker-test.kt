package com.timerz9turbo.app.ui

import com.timerz9turbo.app.R
import com.timerz9turbo.app.data.ManagerScanner.Candidate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TimerManagerPickerTest {
    @Test
    fun `an empty list while loading is not reported as no apps found`() {
        val state = TimerUiState(managerLoading = true)
        assertEquals(R.string.manager_picker_loading, state.managerPickerMessage(false))
        assertEquals(R.string.manager_picker_loading, state.managerPickerMessage(true))
    }

    @Test
    fun `scan failures are distinct from an empty completed scan`() {
        assertEquals(R.string.manager_picker_error, TimerUiState(managerLoadFailed = true).managerPickerMessage(false))
        assertEquals(R.string.manager_picker_empty, TimerUiState().managerPickerMessage(true))
    }

    @Test
    fun `show all exposes apps whose daemon will be inspected only when running`() {
        val state = TimerUiState(managerCandidates = listOf(Candidate("com.sukisu.ultra", "SukiSU", false, true)))
        assertEquals(R.string.manager_picker_no_detected, state.managerPickerMessage(false))
        assertNull(state.managerPickerMessage(true))
    }

    @Test
    fun `the default fast scan still exposes apps with libksud`() {
        val state = TimerUiState(managerCandidates = listOf(Candidate("me.weishu.kernelsu", "KernelSU", true, true)))
        assertNull(state.managerPickerMessage(false))
    }
}
