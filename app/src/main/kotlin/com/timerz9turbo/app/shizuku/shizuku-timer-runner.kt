package com.timerz9turbo.app.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import com.timerz9turbo.app.BuildConfig
import com.timerz9turbo.app.domain.model.ShizukuStatus
import kotlinx.coroutines.suspendCancellableCoroutine
import rikka.shizuku.Shizuku
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

class ShizukuTimerRunner(private val context: Context) {
    private var statusListener: (() -> Unit)? = null
    private val binderReceived = Shizuku.OnBinderReceivedListener { statusListener?.invoke() }
    private val binderDead = Shizuku.OnBinderDeadListener { statusListener?.invoke() }
    private val permissionResult = Shizuku.OnRequestPermissionResultListener { requestCode, _ ->
        if (requestCode == PERMISSION_REQUEST) statusListener?.invoke()
    }

    init {
        Shizuku.addBinderReceivedListenerSticky(binderReceived)
        Shizuku.addBinderDeadListener(binderDead)
        Shizuku.addRequestPermissionResultListener(permissionResult)
    }

    fun status(): ShizukuStatus = runCatching {
        when {
            !Shizuku.pingBinder() || Shizuku.getUid() != Process.SHELL_UID -> ShizukuStatus.NOT_RUNNING
            Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED -> ShizukuStatus.PERMISSION_REQUIRED
            else -> ShizukuStatus.READY
        }
    }.getOrDefault(ShizukuStatus.NOT_RUNNING)

    fun requestPermission() {
        if (status() == ShizukuStatus.PERMISSION_REQUIRED) Shizuku.requestPermission(PERMISSION_REQUEST)
    }
    fun setStatusListener(listener: (() -> Unit)?) { statusListener = listener }

    suspend fun run(safeMode: Boolean, debugDir: String?, managerPackage: String?, onLog: (String) -> Unit): Int =
        execute(onLog) { service, callback -> service.runTimer(safeMode, debugDir, managerPackage, callback) }

    suspend fun runDiagnose(onLog: (String) -> Unit): Int =
        execute(onLog) { service, callback -> service.runDiagnose(callback) }

    private suspend fun execute(onLog: (String) -> Unit, start: (ITimerUserService, ITimerCallback) -> Unit): Int {
        val current = status()
        onLog("<s> status=$current")
        if (current != ShizukuStatus.READY) { onLog("<s> error: Shizuku is not ready"); return 1 }
        repeat(3) {
            val result = connect(onLog, start)
            if (result != null) return result
        }
        onLog("<s> error: Shizuku UserService did not connect after 3 attempts")
        return 1
    }

    /** Retry only failed connections; a dispatched Timer run must not be repeated. */
    private suspend fun connect(onLog: (String) -> Unit, start: (ITimerUserService, ITimerCallback) -> Unit): Int? =
        suspendCancellableCoroutine { continuation ->
            val log = onLog
            val args = Shizuku.UserServiceArgs(ComponentName(context.packageName, TimerUserService::class.java.name))
                .daemon(false).processNameSuffix("timerz9").debuggable(false).version(BuildConfig.VERSION_CODE)
            val handler = Handler(Looper.getMainLooper())
            val completed = AtomicBoolean(false)
            lateinit var connection: ServiceConnection
            lateinit var timeout: Runnable
            fun finish(code: Int?, error: String? = null) {
                if (!completed.compareAndSet(false, true)) return
                handler.removeCallbacks(timeout)
                error?.let { onLog("<s> error: $it") }
                runCatching { Shizuku.unbindUserService(args, connection, true) }
                if (continuation.isActive) continuation.resume(code)
            }
            timeout = Runnable { finish(null, "UserService connection timed out") }
            connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    if (completed.get()) return
                    handler.removeCallbacks(timeout)
                    onLog("<b> Shizuku UserService connected")
                    val callback = object : ITimerCallback.Stub() {
                        override fun onLog(line: String) { if (!completed.get()) log(line) }
                        override fun onComplete(exitCode: Int) = finish(exitCode)
                    }
                    runCatching { start(ITimerUserService.Stub.asInterface(binder), callback) }
                        .onFailure { finish(1, it.message ?: "UserService call failed") }
                }
                override fun onServiceDisconnected(name: ComponentName) = finish(1, "UserService disconnected")
            }
            continuation.invokeOnCancellation {
                if (completed.compareAndSet(false, true)) {
                    handler.removeCallbacks(timeout)
                    runCatching { Shizuku.unbindUserService(args, connection, false) }
                }
            }
            handler.postDelayed(timeout, 3_000L)
            runCatching { Shizuku.bindUserService(args, connection) }
                .onFailure { finish(null, it.message ?: "Cannot bind UserService") }
        }

    fun close() {
        Shizuku.removeBinderReceivedListener(binderReceived)
        Shizuku.removeBinderDeadListener(binderDead)
        Shizuku.removeRequestPermissionResultListener(permissionResult)
        statusListener = null
    }

    private companion object { const val PERMISSION_REQUEST = 4815 }
}
