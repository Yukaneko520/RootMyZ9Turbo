package com.timerz9turbo.app.shizuku

/**
 * Timing shared by the Shizuku and ADB runners.
 *
 * The native backend needs no fixed plant budget: every plant is bounded by an
 * 8 s zombie timeout and a 15 s burst poll that ends as soon as the spray has
 * drained, and a failed plant is retried at most twice.  The window below is
 * sized from the observed worst case (8 plants, ~7 s each, plus the ksud
 * late-load), not from a budget compiled into the binary.
 */
internal object TimerTiming {
    /** How long the app watches the native log/completion file (Shizuku). */
    const val LOG_WATCH_MS = 150_000L

    /** Shell-level wait for the completion file (ADB), in 250 ms polls. */
    const val COMPLETION_POLLS = LOG_WATCH_MS / 250L

    /** Extra allowance for staging, the log tail and the manager probe. */
    const val SHELL_TIMEOUT_MS = LOG_WATCH_MS + 50_000L
}
