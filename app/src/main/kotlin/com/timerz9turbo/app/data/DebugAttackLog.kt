package com.timerz9turbo.app.data

import android.content.ContentValues
import android.content.Context
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import android.provider.DocumentsContract
import com.timerz9turbo.app.domain.model.DebugSettings
import java.io.BufferedWriter
import java.io.Closeable
import java.io.File
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong

/** Debug-only, immediately visible archive for one attack attempt. */
internal class DebugAttackLog private constructor(
    private val context: Context,
    val displayName: String,
    /** Primary-storage-relative folder that holds the attempt log and its dumps. */
    folderPath: String,
    private var writer: BufferedWriter,
) : Closeable {
    var folderPath: String = folderPath
        private set
    var usedFallback: Boolean = false
        private set
    private var fallback: (() -> DebugAttackLog?)? = null
    private val sidecarFolders = linkedSetOf(folderPath)
    private var closed = false

    /** Absolute destination for Timer log copies. */
    @Suppress("DEPRECATION")
    val folderFile: File
        get() = File(Environment.getExternalStorageDirectory(), folderPath)

    @Synchronized
    fun append(line: String) {
        check(!closed) { "debug log is closed" }
        try {
            writeLine(line)
        } catch (failure: Exception) {
            val openFallback = fallback ?: throw failure
            // Retry the failed line only once; retain the earlier SAF log as-is.
            fallback = null
            val replacement = openFallback() ?: throw failure
            val previousWriter = writer
            writer = replacement.writer
            folderPath = replacement.folderPath
            sidecarFolders += folderPath
            usedFallback = true
            runCatching { previousWriter.close() }
            writeLine(line)
        }
    }

    private fun writeLine(line: String) {
        writer.write(line)
        writer.newLine()
        writer.flush()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        fallback = null
        try {
            writer.close()
        } finally {
            publishSidecars()
        }
    }

    /** Ask MediaStore to index the root-written dumps so file managers show them. */
    private fun publishSidecars() {
        runCatching {
            // A running operation may still have written dumps to the original folder.
            @Suppress("DEPRECATION")
            val paths = sidecarFolders.flatMap { folder ->
                File(Environment.getExternalStorageDirectory(), folder).listFiles().orEmpty()
                    .filter { it.isFile }.map { it.absolutePath }
            }
            if (paths.isEmpty()) return
            MediaScannerConnection.scanFile(context, paths.toTypedArray(), null, null)
        }
    }

    companion object {
        private val sequence = AtomicLong()

        fun open(context: Context, entry: String, folder: String, treeUri: Uri? = null): DebugAttackLog? {
            val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
            val suffix = sequence.getAndIncrement()
            val displayName = "timerz9turbo-$entry-$suffix.log"
            if (treeUri == null) return openDestination(context, folder, stamp, displayName)

            val openFallback = {
                openDestination(context, DebugSettings().exportLocation, stamp, displayName)
            }
            val selected = openDestination(context, folder, stamp, displayName, treeUri)
            if (selected != null) {
                selected.fallback = openFallback
                return selected
            }
            return openFallback()?.apply { usedFallback = true }
        }

        private fun openDestination(
            context: Context,
            folder: String,
            stamp: String,
            displayName: String,
            treeUri: Uri? = null,
        ): DebugAttackLog? {
            val resolver = context.contentResolver
            var uri: Uri? = null
            return try {
                var folderPath = "$folder/$stamp"
                uri = if (treeUri != null) {
                    val root = DocumentsContract.buildDocumentUriUsingTree(treeUri, DocumentsContract.getTreeDocumentId(treeUri))
                    val directory = DocumentsContract.createDocument(resolver, root, DocumentsContract.Document.MIME_TYPE_DIR, stamp)
                        ?: return null
                    folderPath = DocumentsContract.getDocumentId(directory).removePrefix("primary:")
                    DocumentsContract.createDocument(resolver, directory, "text/plain", displayName)
                } else {
                    val values = ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
                        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, folderPath)
                    }
                    resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                }
                if (uri == null) return null
                val output = resolver.openOutputStream(uri, "w")
                    ?: error("cannot open debug log output")
                DebugAttackLog(
                    context.applicationContext,
                    displayName,
                    folderPath,
                    BufferedWriter(OutputStreamWriter(output, StandardCharsets.UTF_8)),
                )
            } catch (_: Exception) {
                if (uri != null) runCatching {
                    if (treeUri != null) DocumentsContract.deleteDocument(resolver, uri)
                    else resolver.delete(uri, null, null)
                }
                null
            }
        }
    }
}
