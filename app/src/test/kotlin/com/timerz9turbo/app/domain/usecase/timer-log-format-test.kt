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

    @Test
    fun `a soft failure stays a warning even when it names a stage`() {
        // "stage ..." is also a milestone prefix, so the warning test must win.
        assertEquals(LogTone.Warning, format("[-] stage fake_cred attempt=1 failed, retrying").tone)
        assertEquals(LogTone.Warning, format("[-] plant1 burst missed; holding zombie, retryable").tone)
        assertEquals(LogTone.Warning, format("[!] no KASLR slide -- parking without reap").tone)
    }

    @Test
    fun `completed stages and a ready spray pool read as progress not errors`() {
        assertEquals(LogTone.Success, format("[+] stage fake_cred done in 120ms").tone)
        assertEquals(LogTone.Success, format("[+] spray pool=2048 sockets, 256 per thread").tone)
        assertEquals(LogTone.Success, format("[+] child heartbeat: wake received").tone)
        assertEquals(LogTone.Progress, format("[+] plant1 spray armed, releasing target").tone)
        assertEquals(LogTone.Progress, format("[+] stage fake_cred target=0x1 mode=fake attempt=1").tone)
    }

    @Test
    fun `the binary failure marker wins over a milestone phrase`() {
        // Regression: "no child heartbeat" contains the milestone phrase
        // "child heartbeat", so a milestone match first painted it green.
        assertEquals(LogTone.Error, format("[!] no child heartbeat (n=0)").tone)
        assertEquals(LogTone.Error, format("[!] child report missing (got=0/32)").tone)
        assertEquals(LogTone.Error, format("[!] fake cred page held; reboot to clean").tone)
        // A retry is a soft failure, not a hard error.
        assertEquals(LogTone.Warning, format("[-] plant1 exec succeeded (status=42); retryable").tone)
        // The success twin of the same phrase must stay green.
        assertEquals(LogTone.Success, format("[+] child heartbeat: wake received").tone)
        assertEquals(LogTone.Success, format("[+] child report uid=0 euid=0 resuid=0/0/0").tone)
    }
}
