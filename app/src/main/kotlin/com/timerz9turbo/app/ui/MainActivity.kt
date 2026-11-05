package com.timerz9turbo.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.view.WindowInsetsController
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.timerz9turbo.app.R
import com.timerz9turbo.app.TimerZ9Application

class MainActivity : ComponentActivity() {
    private val viewModel by viewModels<TimerViewModel> {
        viewModelFactory { initializer { TimerViewModel((application as TimerZ9Application).createRepository()) } }
    }
    private val folderPicker = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) viewModel.onDebugExportLocationPicked(documentTreeRelativePath(uri))
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel.initialize()
        setContent {
            val state by viewModel.state.collectAsStateWithLifecycle()
            LaunchedEffect(viewModel) { viewModel.effects.collect(::handleEffect) }
            TimerApp(state, viewModel)
        }
        setupSystemBars()
    }
    override fun onResume() { super.onResume(); viewModel.refreshAccessStatus() }

    private fun documentTreeRelativePath(uri: Uri): String? {
        val id = runCatching { DocumentsContract.getTreeDocumentId(uri) }.getOrNull() ?: return null
        return if (id.startsWith("primary:")) id.substringAfter(':').trim('/').ifEmpty { null } else null
    }
    private fun handleEffect(effect: TimerEffect) {
        when (effect) {
            TimerEffect.PickDebugFolder -> folderPicker.launch(null)
            is TimerEffect.Toast -> Toast.makeText(this, effect.resourceId, Toast.LENGTH_SHORT).show()
            is TimerEffect.Clipboard -> getSystemService(ClipboardManager::class.java)
                ?.setPrimaryClip(ClipData.newPlainText("timerz9turbo-log", effect.text))
            is TimerEffect.KeepScreenAwake -> if (effect.enabled) {
                window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            } else window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
            TimerEffect.OpenShizuku -> packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")?.let(::startActivity)
        }
    }
    private fun setupSystemBars() {
        val controller = window.decorView.windowInsetsController ?: return
        val status = if (resources.getBoolean(R.bool.window_light_status_bar)) WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS else 0
        val navigation = if (resources.getBoolean(R.bool.window_light_navigation_bar)) WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS else 0
        controller.setSystemBarsAppearance(status or navigation,
            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS)
    }
}
