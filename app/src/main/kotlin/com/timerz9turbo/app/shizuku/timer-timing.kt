package com.timerz9turbo.app.shizuku

/**
 * Timing shared by the Shizuku and ADB runners.
 *
 * The native backend arms its plants for at most [NATIVE_PLANT_BUDGET_MS]
 * (PLANT_BUDGET_MS in timer.c) after the credential leak, then parks with a
 * precise reason.  The monitoring windows below must leave room for the leak,
 * the ksu stage and the wrapper script, so they sit above that budget and the
 * native process always gets to report its own result.
 */
internal object TimerTiming {
    /** Plant budget compiled into the native backend. */
    const val NATIVE_PLANT_BUDGET_MS = 110_000L

    /** How long the app watches the native log/completion file (Shizuku). */
    const val LOG_WATCH_MS = 150_000L

    /** Shell-level wait for the completion file (ADB), in 250 ms polls. */
    const val COMPLETION_POLLS = LOG_WATCH_MS / 250L

    /**
     * How long to keep asking the manager for a positive kernel version after
     * the native run completed.  `debug version` reports 0 while the module is
     * loaded but not initialised, so one sample is not evidence of failure.
     */
    const val CONFIRM_WATCH_MS = 20_000L

    /** RPC timeout for the whole ADB shell run. */
    const val SHELL_TIMEOUT_MS = LOG_WATCH_MS + 50_000L
}
