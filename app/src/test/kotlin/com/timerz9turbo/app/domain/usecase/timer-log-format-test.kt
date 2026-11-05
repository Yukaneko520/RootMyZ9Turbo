package com.timerz9turbo.app.domain.usecase

import com.timerz9turbo.app.domain.model.LogTone
import org.junit.Assert.assertEquals
import org.junit.Test

class TimerLogFormatTest {
    private val format = FormatLogUseCase()

    @Test
    fun `native loaded marker and final failure have distinct tones`() {
        assertEquals(LogTone.Success, format("KSU_LOADED").tone)
        assertEquals(LogTone.Error, format("<k> result: failed (exit code=1)").tone)
        assertEquals(LogTone.Error, format("<s> error: ksud missing").tone)
    }

    @Test
    fun `ANSI sequences are stripped while retaining line separation`() {
        assertEquals("[+] writes landed\n", format("\u001b[32m[+] writes landed\u001b[0m").text)
    }
}
