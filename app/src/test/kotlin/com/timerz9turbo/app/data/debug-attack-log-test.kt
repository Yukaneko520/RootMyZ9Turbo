package com.timerz9turbo.app.data

import android.Manifest
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsProvider
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowContentResolver

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class DebugAttackLogTest {
    @get:Rule val storage = TemporaryFolder()

    @Test
    fun `a selected folder outside Download receives the actual log file`() {
        val context = RuntimeEnvironment.getApplication()
        val authority = "com.android.externalstorage.documents"
        val provider = LogDocumentsProvider(storage.root)
        provider.attachInfo(context, ProviderInfo().apply {
            this.authority = authority
            exported = true
            grantUriPermissions = true
            readPermission = Manifest.permission.MANAGE_DOCUMENTS
            writePermission = Manifest.permission.MANAGE_DOCUMENTS
            applicationInfo = context.applicationInfo
        })
        ShadowContentResolver.registerProviderInternal(authority, provider)
        val tree = Uri.parse("content://$authority/tree/primary%3AZ9tb")
        val archive = DebugAttackLog.open(context, "timer", "Z9tb", tree)
        assertNotNull(archive)
        archive!!
        archive.append("kernel confirmed: version=41150")
        archive.close()
        val session = File(storage.root, "Z9tb").listFiles()!!.single { it.isDirectory }
        val output = session.listFiles()!!.single()
        assertEquals(listOf("kernel confirmed: version=41150"), output.readLines())
        assertEquals("Z9tb/${session.name}", archive.folderPath)
    }
}

private class LogDocumentsProvider(private val storage: File) : DocumentsProvider() {
    override fun onCreate(): Boolean = File(storage, "Z9tb").mkdirs()

    override fun queryRoots(projection: Array<out String>?): Cursor = MatrixCursor(emptyArray())

    override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor =
        documents(listOf(documentId), projection)

    override fun queryChildDocuments(parentDocumentId: String, projection: Array<out String>?, sortOrder: String?): Cursor =
        documents(file(parentDocumentId).listFiles().orEmpty().map { "primary:${it.relativeTo(storage).invariantSeparatorsPath}" }, projection)

    override fun isChildDocument(parentDocumentId: String, documentId: String): Boolean =
        documentId.startsWith("$parentDocumentId/")

    override fun createDocument(parentDocumentId: String, mimeType: String, displayName: String): String {
        val destination = File(file(parentDocumentId), displayName)
        check(if (mimeType == Document.MIME_TYPE_DIR) destination.mkdir() else destination.createNewFile())
        return "primary:${destination.relativeTo(storage).invariantSeparatorsPath}"
    }

    override fun openDocument(documentId: String, mode: String, signal: CancellationSignal?): ParcelFileDescriptor =
        ParcelFileDescriptor.open(file(documentId), ParcelFileDescriptor.parseMode(mode))

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
