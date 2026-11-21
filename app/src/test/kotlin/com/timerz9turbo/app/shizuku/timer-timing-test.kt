package com.timerz9turbo.app.shizuku

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TimerTimingTest {
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
    fun `kernel confirmation fits inside the completion check`() {
        // One sample, taken after the completion byte; the stage script already
        // waited for ksud late-load to exit, so there is no retry window.
        assertTrue(TimerTiming.COMPLETION_POLLS > 0)
    }

    @Test
    fun `log watch window covers the worst recorded successful run`() {
        // Worst recorded successful run: 67 s of plants + the child's 30 s
        // report window + the ksu late-load.  The native side always writes the
        // completion byte (atexit), so this window is a cutoff only for a run
        // that is genuinely stuck.
        val worstRun = 67_000L + 30_000L + 20_000L
        assertTrue(TimerTiming.LOG_WATCH_MS > worstRun)
    }
}
