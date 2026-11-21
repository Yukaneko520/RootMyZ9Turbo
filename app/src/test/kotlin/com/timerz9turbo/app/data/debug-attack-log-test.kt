package com.timerz9turbo.app.data

import android.Manifest
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import android.provider.MediaStore
import com.timerz9turbo.app.domain.model.DebugSettings
import java.io.File
import java.io.IOException
import java.io.OutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowContentResolver

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class DebugAttackLogTest {
    @get:Rule val storage = TemporaryFolder()
    private lateinit var documents: LogDocumentsProvider
    private lateinit var downloads: LogDownloadsProvider
    private val context get() = RuntimeEnvironment.getApplication()
    private val authority = "com.android.externalstorage.documents"
    private val tree get() = Uri.parse("content://$authority/tree/primary%3AZ9tb")

    @Before
    fun registerProviders() {
        documents = LogDocumentsProvider(storage.root)
        documents.attachInfo(context, ProviderInfo().apply {
            authority = this@DebugAttackLogTest.authority
            exported = true
            grantUriPermissions = true
            readPermission = Manifest.permission.MANAGE_DOCUMENTS
            writePermission = Manifest.permission.MANAGE_DOCUMENTS
            applicationInfo = context.applicationInfo
        })
        ShadowContentResolver.registerProviderInternal(authority, documents)
        downloads = LogDownloadsProvider(storage.newFolder("downloads"))
        downloads.attachInfo(context, ProviderInfo().apply {
            authority = MediaStore.AUTHORITY
            applicationInfo = context.applicationInfo
        })
        ShadowContentResolver.registerProviderInternal(MediaStore.AUTHORITY, downloads)
    }

    @Test
    fun `a selected folder outside Download receives the actual log file`() {
        val archive = DebugAttackLog.open(context, "timer", "Z9tb", tree)
        assertNotNull(archive)
        archive!!
        archive.append("kernel confirmed: version=41150")
        archive.close()
        val session = File(storage.root, "Z9tb").listFiles()!!.single { it.isDirectory }
        val output = session.listFiles()!!.single()
        assertEquals(listOf("kernel confirmed: version=41150"), output.readLines())
        assertEquals("Z9tb/${session.name}", archive.folderPath)
        assertEquals(0, downloads.insertCount)
    }

    @Test
    fun `revoked SAF permission falls back to default Downloads`() {
        documents.failure = "directory-throws"
        assertFallback()
    }

    @Test
    fun `null SAF directory falls back to default Downloads`() {
        documents.failure = "directory-null"
        assertFallback()
    }

    @Test
    fun `failed SAF log creation falls back to default Downloads`() {
        documents.failure = "file-throws"
        assertFallback()
    }

    @Test
    fun `null SAF log falls back to default Downloads`() {
        documents.failure = "file-null"
        assertFallback()
    }

    @Test
    fun `failed SAF stream open cleans up the document and falls back`() {
        documents.failure = "open-throws"
        assertFallback()
        assertEquals(1, documents.deleteCount)
    }

    @Test
    fun `null SAF stream cleans up the document and falls back`() {
        documents.failure = "open-null"
        assertFallback()
        assertEquals(1, documents.deleteCount)
    }

    @Test
    fun `cleanup failure does not prevent fallback`() {
        documents.failure = "open-throws"
        documents.failDelete = true
        assertFallback()
        assertEquals(1, documents.deleteCount)
    }

    @Test
    fun `malformed tree falls back to default Downloads`() {
        assertFallback(Uri.parse("content://$authority/not-a-tree"))
    }

    @Test
    fun `MediaStore still uses the configured folder without a SAF tree`() {
        val archive = DebugAttackLog.open(context, "timer", "Download/custom")!!
        archive.use { it.append("custom log") }
        assertEquals("Download/custom", archive.folderPath.substringBeforeLast('/'))
        assertEquals(archive.folderPath, downloads.lastValues!!.getAsString(MediaStore.MediaColumns.RELATIVE_PATH))
        assertEquals(listOf("custom log"), downloads.logFile.readLines())
    }

    @Test
    fun `both destinations failing returns null`() {
        documents.failure = "directory-throws"
        downloads.failure = "insert-throws"
        assertNull(DebugAttackLog.open(context, "timer", "Z9tb", tree))
        assertEquals(1, downloads.insertCount)
    }

    @Test
    fun `null MediaStore insertion returns null`() {
        documents.failure = "directory-null"
        downloads.failure = "insert-null"
        assertNull(DebugAttackLog.open(context, "timer", "Z9tb", tree))
    }

    @Test
    fun `failed fallback stream is cleaned up`() {
        documents.failure = "directory-null"
        downloads.failure = "open-throws"
        assertNull(DebugAttackLog.open(context, "timer", "Z9tb", tree))
        assertEquals(1, downloads.deleteCount)
    }

    @Test
    fun `null fallback stream is cleaned up`() {
        documents.failure = "directory-null"
        downloads.failure = "open-null"
        assertNull(DebugAttackLog.open(context, "timer", "Z9tb", tree))
        assertEquals(1, downloads.deleteCount)
    }

    @Test
    fun `SAF write failure retries the line and continues in Downloads`() {
        documents.failure = "write-throws"
        assertFallback()
    }

    @Test
    fun `late SAF write failure preserves earlier lines and moves subsequent lines to Downloads`() {
        documents.failure = "second-write-throws"
        val archive = DebugAttackLog.open(context, "timer", "Z9tb", tree)!!
        archive.use {
            it.append("first SAF line")
            assertEquals(0, downloads.insertCount)
            it.append("retry this line")
            it.append("next line")
        }
        val session = File(storage.root, "Z9tb").listFiles()!!.single()
        assertEquals(listOf("first SAF line"), session.listFiles()!!.single().readLines())
        assertEquals(listOf("retry this line", "next line"), downloads.logFile.readLines())
        assertDefaultDestination(archive)
    }

    @Test
    fun `runtime fallback failure is surfaced and is not retried indefinitely`() {
        documents.failure = "write-throws"
        downloads.failure = "insert-throws"
        val archive = DebugAttackLog.open(context, "timer", "Z9tb", tree)!!
        assertThrows(IOException::class.java) { archive.append("first failed line") }
        assertThrows(IOException::class.java) { archive.append("second failed line") }
        assertEquals(1, downloads.insertCount)
        runCatching { archive.close() }
    }

    @Test
    fun `MediaStore write failure after runtime fallback is surfaced without another fallback`() {
        documents.failure = "write-throws"
        downloads.failure = "write-throws"
        val archive = DebugAttackLog.open(context, "timer", "Z9tb", tree)!!
        assertThrows(IOException::class.java) { archive.append("failed in both destinations") }
        assertTrue(archive.usedFallback)
        assertThrows(IOException::class.java) { archive.append("still unavailable") }
        assertEquals(1, downloads.insertCount)
        runCatching { archive.close() }
        assertTrue(documents.outputClosed)
        assertTrue(downloads.outputClosed)
    }

    @Test
    fun `closing SAF log prevents later writes from creating fallback files`() {
        val archive = DebugAttackLog.open(context, "timer", "Z9tb", tree)!!
        archive.close()
        archive.close()
        assertThrows(IllegalStateException::class.java) { archive.append("after close") }
        assertEquals(0, downloads.insertCount)
    }

    @Test
    fun `fallback does not change saved folder preferences`() {
        val repository = TimerRepository(context)
        try {
            repository.setDebugExportLocation("Z9tb", tree.toString())
            documents.failure = "directory-throws"
            assertFallback()
            assertEquals("Z9tb", repository.debugSettings().exportLocation)
            val preferences = context.getSharedPreferences("ghostlock_prefs", Context.MODE_PRIVATE)
            assertEquals(tree.toString(), preferences.getString("debug_export_tree_uri", null))
        } finally {
            repository.close()
        }
    }

    private fun assertFallback(selectedTree: Uri = tree) {
        val archive = DebugAttackLog.open(context, "timer", "Z9tb", selectedTree)
        assertNotNull(archive)
        archive!!.use {
            it.append("kernel confirmed: version=41150")
            it.append("second line")
        }
        assertDefaultDestination(archive)
        assertEquals(listOf("kernel confirmed: version=41150", "second line"), downloads.logFile.readLines())
    }

    private fun assertDefaultDestination(archive: DebugAttackLog) {
        assertTrue(archive.usedFallback)
        assertEquals(1, downloads.insertCount)
        assertEquals(DebugSettings().exportLocation, archive.folderPath.substringBeforeLast('/'))
        assertEquals(archive.folderPath, downloads.lastValues!!.getAsString(MediaStore.MediaColumns.RELATIVE_PATH))
        assertEquals(archive.displayName, downloads.lastValues!!.getAsString(MediaStore.MediaColumns.DISPLAY_NAME))
        assertTrue(archive.folderFile.invariantSeparatorsPath.endsWith("/${archive.folderPath}"))
    }
}

private class LogDocumentsProvider(private val storage: File) : DocumentsProvider() {
    var failure: String? = null
    var failDelete = false
    var deleteCount = 0
    var outputClosed = false
    override fun onCreate(): Boolean = File(storage, "Z9tb").mkdirs()

    override fun queryRoots(projection: Array<out String>?): Cursor = MatrixCursor(emptyArray())

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor =
        documents(listOf(documentId), projection)

    override fun queryChildDocuments(parentDocumentId: String, projection: Array<out String>?, sortOrder: String?): Cursor =
        documents(file(parentDocumentId).listFiles().orEmpty().map { "primary:${it.relativeTo(storage).invariantSeparatorsPath}" }, projection)

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean =
        documentId.startsWith("$parentDocumentId/")

    override fun createDocument(parentDocumentId: String, mimeType: String, displayName: String): String? {
        val stage = if (mimeType == Document.MIME_TYPE_DIR) "directory" else "file"
        if (failure == "$stage-throws") throw SecurityException("SAF permission revoked")
        if (failure == "$stage-null") return null
        val destination = File(file(parentDocumentId), displayName)
        check(if (mimeType == Document.MIME_TYPE_DIR) destination.mkdir() else destination.createNewFile())
        val id = "primary:${destination.relativeTo(storage).invariantSeparatorsPath}"
        if (stage == "file" && failure in listOf("write-throws", "second-write-throws")) {
            val uri = DocumentsContract.buildDocumentUriUsingTree(
                Uri.parse("content://com.android.externalstorage.documents/tree/primary%3AZ9tb"), id,
            )
            val output = destination.outputStream()
            shadowOf(context!!.contentResolver).registerOutputStream(uri, object : OutputStream() {
                private var writes = 0
                override fun write(value: Int) = throw IOException("SAF write failed")
                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    if (failure == "write-throws" || writes++ > 0) throw IOException("SAF write failed")
                    output.write(bytes, offset, length)
                }
                override fun close() {
                    outputClosed = true
                    output.close()
                }
            })
        }
        return id
    }

    override fun openDocument(documentId: String, mode: String, signal: CancellationSignal?): ParcelFileDescriptor? {
        if (failure == "open-throws") throw IOException("Cannot open SAF log")
        if (failure == "open-null") return null
        return ParcelFileDescriptor.open(file(documentId), ParcelFileDescriptor.parseMode(mode))
    }

    override fun deleteDocument(documentId: String) {
        deleteCount++
        if (failDelete) throw SecurityException("Cannot delete SAF log")
        check(file(documentId).delete())
    }

    private fun file(id: String) = File(storage, id.removePrefix("primary:"))

    private fun documents(ids: List<String>, projection: Array<out String>?): Cursor {
        val columns = projection ?: arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE, Document.COLUMN_FLAGS)
        return MatrixCursor(columns).apply {
            ids.forEach { id ->
                val target = file(id)
                addRow(columns.map { column -> when (column) {
                    Document.COLUMN_DOCUMENT_ID -> id
                    Document.COLUMN_DISPLAY_NAME -> target.name
                    Document.COLUMN_MIME_TYPE -> if (target.isDirectory) Document.MIME_TYPE_DIR else "text/plain"
                    Document.COLUMN_FLAGS -> Document.FLAG_SUPPORTS_WRITE or Document.FLAG_DIR_SUPPORTS_CREATE
                    else -> null
                } })
            }
        }
    }
}

private class LogDownloadsProvider(private val storage: File) : ContentProvider() {
    var failure: String? = null
    var insertCount = 0
    var deleteCount = 0
    var lastValues: ContentValues? = null
    var outputClosed = false
    val logFile get() = File(storage, "log.txt")

    override fun onCreate() = true
    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        insertCount++
        lastValues = values?.let(::ContentValues)
        if (failure == "insert-throws") throw SecurityException("Downloads unavailable")
        if (failure == "insert-null") return null
        val result = Uri.withAppendedPath(uri, insertCount.toString())
        if (failure == "write-throws") {
            shadowOf(context!!.contentResolver).registerOutputStream(result, object : OutputStream() {
                override fun write(value: Int) = throw IOException("Downloads write failed")
                override fun close() { outputClosed = true }
            })
        }
        return result
    }
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        if (failure == "open-throws") throw IOException("Cannot open Downloads log")
        if (failure == "open-null") return null
        return ParcelFileDescriptor.open(logFile, ParcelFileDescriptor.parseMode(mode))
    }
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
        deleteCount++
        logFile.delete()
        return 1
    }
    override fun getType(uri: Uri) = "text/plain"
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
