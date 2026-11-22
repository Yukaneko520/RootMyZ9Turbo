package com.timerz9turbo.app.domain.usecase

import com.timerz9turbo.app.domain.model.LogEntry
import com.timerz9turbo.app.domain.model.LogTone

class FormatLogUseCase {
    operator fun invoke(line: String): LogEntry {
        val text = stripAnsi(if (line.endsWith('\n')) line else "$line\n")
        val body = text.replaceFirst(sourceTag, "")
        val marker = body.getOrNull(1).takeIf { body.startsWith('[') && body.getOrNull(2) == ']' }
        val tagged = text
            .removePrefix("<-> ")
            .removePrefix("<b> ")
            .removePrefix("<s> ")
            .removePrefix("<k> ")
        val tone = when {
            text.startsWith("<->") -> LogTone.Error
            text.startsWith("<b>") ->
                if (tagged.contains("connected") && !tagged.contains("disconnected")) {
                    LogTone.Success
                } else {
                    LogTone.Progress
                }

            text.startsWith("<s>") -> if (looksLikeError(tagged)) LogTone.Error else LogTone.Shizuku
            text.startsWith("<k>") ->
                if (tagged.startsWith("result:")) resultTone(tagged) else LogTone.Kotlin

            tagged.startsWith("result:") -> resultTone(tagged)
            /*
             * Order matters here, and the recorded logs pinned it:
             *  1. A soft failure is a warning even when it repeats a milestone
             *     word ("stage ... failed, retrying").
             *  2. `[!]` / `[-]` are the binary's failure markers.  "no child
             *     heartbeat" contains the milestone phrase "child heartbeat",
             *     so a milestone match allowed first painted a failed run green.
             *  3. Milestones and progress only refine a non-failing line.
             */
            isTimerSoftFail(tagged) -> LogTone.Warning
            marker == '-' || marker == '!' -> LogTone.Error
            isTimerMilestone(tagged) -> LogTone.Success
            isTimerProgress(tagged) -> LogTone.Progress
            marker == '+' -> LogTone.Success
            marker == '*' -> LogTone.Warning
            body.startsWith("error", ignoreCase = true) -> LogTone.Error
            body.startsWith("warning", ignoreCase = true) -> LogTone.Warning
            else -> LogTone.Default
        }
        return LogEntry(text, tone)
    }

    /*
     * Milestones are matched only on positive lines: a `[!]` marker is already
     * an error, and a soft failure is checked first, so a phrase shared by a
     * success and a failure cannot hide the failure.
     */
    private fun isTimerMilestone(line: String): Boolean = listOf(
        "OK (attempt", "de-tag done", "writes landed", "KSU_LOADED",
        "woke uid=0 euid=0", "uid=0 euid=0", "late-load rc=0", "kill disabled",
        "done in", "spray pool", "heartbeat: wake received",
        "child report uid=", "fake cred A=",
    ).any(line::contains)

    /* Soft failure: run continues, operator should notice (yellow, not red). */
    private fun isTimerSoftFail(line: String): Boolean = listOf(
        "retrying", "retryable", "burst missed", "holding zombie", "exec succeeded",
        "no KASLR slide", "no spray sockets", "cannot write /data/local/tmp/ksu_stage.sh",
    ).any(line::contains)

    private fun isTimerProgress(line: String): Boolean = listOf(
        "] stage ", "plant1 ", "recs=", "slab", "burst", "free_seen", "reaped",
        "write mode=", "fake cred ", "[ids]", "[base]", "[cred]", "[slab]",
        "endgame", "de-tag:", "pid=", "made=", "[diag]",
    ).any(line::contains)

    private fun resultTone(text: String): LogTone =
        if (listOf("failed", "unsupported", "cancelled").any(text::contains)) LogTone.Error else LogTone.Success

    private fun looksLikeError(text: String): Boolean {
        val lower = text.lowercase()
        return lower.startsWith("error") ||
                listOf("fail", "cannot", "unable", "denied", "refus").any(lower::contains)
    }

    private fun stripAnsi(value: String): String = value.replace(ansi, "")

    private companion object {
        val ansi = Regex("\\u001B\\[[;\\d]*m")
        val sourceTag = Regex("^\\[[a-z]+]\\s+")
    }
}
