package com.timerz9turbo.app.shizuku

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TimerTimingTest {
    @Test
    fun `monitoring window never cuts off the native plant budget`() {
        assertTrue(TimerTiming.LOG_WATCH_MS > TimerTiming.NATIVE_PLANT_BUDGET_MS)
    }

    @Test
    fun `adb shell timeout covers the completion poll loop`() {
        val pollWindow = TimerTiming.COMPLETION_POLLS * 250L
        assertEquals(TimerTiming.LOG_WATCH_MS, pollWindow)
        assertTrue(TimerTiming.SHELL_TIMEOUT_MS > pollWindow)
    }

    @Test
    fun `completion poll count matches the documented 250 ms cadence`() {
        assertEquals(600L, TimerTiming.COMPLETION_POLLS)
    }

    @Test
    fun `kernel confirmation window fits inside the log watch window`() {
        assertTrue(TimerTiming.CONFIRM_WATCH_MS in 1..TimerTiming.LOG_WATCH_MS)
    }
}
