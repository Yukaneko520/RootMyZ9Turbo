package com.timerz9turbo.app

import android.app.Application
import com.timerz9turbo.app.data.TimerRepository

class TimerZ9Application : Application() {
    fun createRepository() = TimerRepository(this)
}
