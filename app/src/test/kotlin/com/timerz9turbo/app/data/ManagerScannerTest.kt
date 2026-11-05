package com.timerz9turbo.app.data

import com.timerz9turbo.app.data.ManagerScanner.Candidate
import org.junit.Assert.assertEquals
import org.junit.Test

class ManagerScannerTest {
    private fun candidate(
        pkg: String,
        hasKsud: Boolean = true,
        builtin: Boolean = pkg in ManagerScanner.BUILTIN,
        label: String = pkg,
    ) = Candidate(pkg, label, hasKsud, builtin)

    @Test
    fun `sort puts compatible builtins first then compatible then label order`() {
        val sorted = listOf(
            candidate("z.app", hasKsud = false, label = "Zeta"),
            candidate("me.weishu.kernelsu"),
            candidate("a.app", hasKsud = false, label = "Alpha"),
            candidate("m.app", hasKsud = true, label = "Mid"),
        ).sortedWith(ManagerScanner.sortComparator())
        assertEquals(
            listOf("me.weishu.kernelsu", "m.app", "a.app", "z.app"),
            sorted.map { it.packageName },
        )
    }
}
