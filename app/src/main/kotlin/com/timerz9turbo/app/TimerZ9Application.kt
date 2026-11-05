package com.timerz9turbo.app

import android.app.Application
import com.timerz9turbo.app.data.AndroidGhostlockRepository
import com.timerz9turbo.app.domain.repository.GhostlockRepository

/** Application composition root. It is the only place that binds data implementations to domain ports. */
class TimerZ9Application : Application() {
    fun createRepository(): GhostlockRepository = AndroidGhostlockRepository(this)
}
