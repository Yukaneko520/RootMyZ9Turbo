package com.timerz9turbo.app.adb

import android.content.Context
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AdbRootPreferencesTest {
    private lateinit var context: Context
    private lateinit var preferences: AdbRootPreferences

    @Before
    fun setUp() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("adb_root_prefs", Context.MODE_PRIVATE).edit().clear().commit()
        preferences = AdbRootPreferences(context)
    }

    @Test
    fun `defaults match the documented settings`() {
        val settings = preferences.settings()
        assertFalse(settings.manualEnabled)
        assertFalse(settings.setupComplete)
        assertFalse(settings.keyAuthorized)
    }

    @Test
    fun `settings round trip through the preferences file`() {
        preferences.manualAdbEnabled = true
        preferences.setupComplete = true
        preferences.keyAuthorized = true
        val settings = AdbRootPreferences(context).settings()
        assertTrue(settings.manualEnabled)
        assertTrue(settings.setupComplete)
        assertTrue(settings.keyAuthorized)
    }

    @Test
    fun `preferences write to device protected storage context`() {
        preferences.manualAdbEnabled = true
        val deContext = context.createDeviceProtectedStorageContext()
        val dePrefs = deContext.getSharedPreferences("adb_root_prefs", Context.MODE_PRIVATE)
        assertTrue(dePrefs.getBoolean("manual_enabled", false))
    }

    @Test
    fun `AdbKeyManager creates, persists, and signs token correctly`() {
        val manager = AdbKeyManager(context)
        val info = manager.ensure()
        assertTrue(info.base64.isNotBlank())
        assertTrue(info.line.contains("timerz9@"))
        assertTrue(info.md5Fingerprint.matches(Regex("([0-9A-F]{2}:){15}[0-9A-F]{2}")))
        assertTrue(info.sha256Fingerprint.matches(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}")))
        assertEquals(info, manager.current())

        // Token signing verification:
        val token = ByteArray(20) { (it * 3 + 1).toByte() }
        val signature = manager.signToken(token)
        assertTrue(signature.isNotEmpty())

        // Reopen new manager instance to verify persistence:
        val reopened = AdbKeyManager(context)
        val reopenedInfo = reopened.current()
        assertEquals(info.base64, reopenedInfo?.base64)
        assertEquals(info.md5Fingerprint, reopenedInfo?.md5Fingerprint)
        assertEquals(info.sha256Fingerprint, reopenedInfo?.sha256Fingerprint)

        val signatureReopened = reopened.signToken(token)
        assertTrue(signatureReopened.isNotEmpty())

        // Verification: fresh manager can sign token immediately without calling current() first
        val freshManager = AdbKeyManager(context)
        val freshSig = freshManager.signToken(token)
        assertTrue(freshSig.isNotEmpty())

        // Verification: self-healing when backup public key file is missing
        val backupFile = java.io.File(java.io.File(context.filesDir, "adb"), "adb_public_key.pub")
        assertTrue(backupFile.isFile)
        backupFile.delete()
        assertFalse(backupFile.isFile)

        val healedManager = AdbKeyManager(context)
        val healedInfo = healedManager.current()
        assertEquals(info.base64, healedInfo?.base64)
        assertEquals(info.md5Fingerprint, healedInfo?.md5Fingerprint)
        assertEquals(info.sha256Fingerprint, healedInfo?.sha256Fingerprint)
        assertTrue(backupFile.isFile) // Recreated automatically
    }

    @Test
    fun `localSnapshot on fresh instance immediately provides fingerprints and reflects not authorized`() {
        val keys = AdbKeyManager(context)
        val conn = AdbConnectionManager(context, preferences, keys)
        val setup = AdbSetupManager(context, preferences, keys, conn)

        val snapshot = setup.localSnapshot()
        // Fingerprints must be present immediately on initial launch:
        assertTrue(snapshot.keyFingerprint?.matches(Regex("([0-9A-F]{2}:){15}[0-9A-F]{2}")) == true)
        assertTrue(snapshot.keyFingerprintSha256?.matches(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}")) == true)
        // Key is not authorized yet:
        assertFalse(snapshot.keyOk)
        assertFalse(snapshot.adbKeyAuthorized)
        assertFalse(snapshot.keyRejected)

        // Simulate successful authorization:
        preferences.keyAuthorized = true
        val authorizedSnapshot = setup.localSnapshot()
        assertTrue(authorizedSnapshot.adbKeyAuthorized)
        assertTrue(authorizedSnapshot.keyOk)
        assertFalse(authorizedSnapshot.keyRejected)

        // Simulate rejection / cancellation:
        preferences.keyAuthorized = false
        preferences.keyRejected = true
        val rejectedSnapshot = setup.localSnapshot()
        assertFalse(rejectedSnapshot.adbKeyAuthorized)
        assertFalse(rejectedSnapshot.keyOk)
        assertTrue(rejectedSnapshot.keyRejected)
    }

    @Test
    fun `AdbClient performs handshake and signs token with real AdbKeyManager`() {
        val manager = AdbKeyManager(context)
        val info = manager.ensure()
        val tokenToSign = ByteArray(20) { (it + 5).toByte() }

        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                val future = executor.submit<Pair<ByteArray, String?>> {
                    server.accept().use { socket ->
                        val input = DataInputStream(socket.getInputStream())
                        val output = DataOutputStream(socket.getOutputStream())
                        assertEquals(AdbProtocol.A_CNXN, AdbProtocol.readPacket(input).command)

                        // Challenge with token:
                        AdbProtocol.writePacket(output, AdbProtocol.A_AUTH, AdbProtocol.AUTH_TOKEN, 0, tokenToSign)
                        val sigPacket = AdbProtocol.readPacket(input)
                        assertEquals(AdbProtocol.A_AUTH, sigPacket.command)
                        assertEquals(AdbProtocol.AUTH_SIGNATURE, sigPacket.arg0)

                        // Request authorization by challenging a second time:
                        AdbProtocol.writePacket(output, AdbProtocol.A_AUTH, AdbProtocol.AUTH_TOKEN, 0, tokenToSign)
                        val pubPacket = AdbProtocol.readPacket(input)
                        assertEquals(AdbProtocol.A_AUTH, pubPacket.command)
                        assertEquals(AdbProtocol.AUTH_RSAPUBLICKEY, pubPacket.arg0)
                        val pubString = String(pubPacket.payload, StandardCharsets.UTF_8)

                        // Accept:
                        AdbProtocol.writePacket(
                            output,
                            AdbProtocol.A_CNXN,
                            AdbProtocol.VERSION,
                            AdbProtocol.MAX_PAYLOAD,
                            "device::".toByteArray(StandardCharsets.UTF_8),
                        )
                        Pair(sigPacket.payload, pubString)
                    }
                }

                AdbClient(
                    port = server.localPort,
                    authenticator = manager,
                    connectTimeoutMs = 2_000,
                    defaultReadTimeoutMs = 5_000,
                    requestAuthorization = true,
                ).use { it.connect() }

                val (signature, pubLine) = future.get(10, TimeUnit.SECONDS)
                assertTrue(signature.isNotEmpty())
                assertTrue(pubLine?.startsWith(info.base64) == true)
                assertTrue(pubLine?.endsWith("\u0000") == true)
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test
    fun `setup snapshot synchronizes preferences setupComplete with root inspection`() {
        val keys = AdbKeyManager(context)
        val conn = AdbConnectionManager(context, preferences, keys)
        val setup = AdbSetupManager(context, preferences, keys, conn)

        // Precondition: preferences had setupComplete marked true:
        preferences.setupComplete = true
        assertTrue(preferences.setupComplete)

        // When snapshot is incomplete (missing port), preferences.setupComplete must become false:
        kotlinx.coroutines.runBlocking {
            val snapshot = setup.snapshot()
            assertFalse(snapshot.setupComplete)
            assertFalse(preferences.setupComplete)
        }
    }

    @Test
    fun `NONEwithRSA signature matches unhashed token whereas SHA1withRSA fails`() {
        val keyPair = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val token = ByteArray(20) { (it * 9 + 3).toByte() }

        // Raw signing produces digest containing exact token:
        val rawSig = java.security.Signature.getInstance("NONEwithRSA").apply {
            initSign(keyPair.private)
            update(AdbPublicKey.sha1DigestInfo(token))
        }.sign()

        val rawVerified = java.security.Signature.getInstance("NONEwithRSA").apply {
            initVerify(keyPair.public)
            update(AdbPublicKey.sha1DigestInfo(token))
        }.verify(rawSig)
        assertTrue(rawVerified)

        // If a key mistakenly signed via SHA1withRSA, the decrypted digest contains SHA-1(token), not token:
        val sha1Sig = java.security.Signature.getInstance("SHA1withRSA").apply {
            initSign(keyPair.private)
            update(token)
        }.sign()

        // Verifying against the unhashed token (what adbd does) fails:
        val sha1AgainstTokenVerified = java.security.Signature.getInstance("NONEwithRSA").apply {
            initVerify(keyPair.public)
            update(AdbPublicKey.sha1DigestInfo(token))
        }.verify(sha1Sig)
        assertFalse(sha1AgainstTokenVerified)
    }

    @Test
    fun `existing software key is preserved and corrupted backup file is repaired`() {
        // Clear Keystore alias if Keystore provider is present
        val store = runCatching {
            java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        }.getOrNull()
        store?.deleteEntry("timerz9_adb_key")

        // Create software key on disk
        val adbDir = java.io.File(context.filesDir, "adb").apply { mkdirs() }
        val privFile = java.io.File(adbDir, "adb_private_key.pk8")
        val pubFile = java.io.File(adbDir, "adb_public_key.pub")

        val kpg = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val pair = kpg.generateKeyPair()
        privFile.writeBytes(pair.private.encoded)

        // Write corrupt/tampered content into pubFile
        pubFile.writeText("corrupted_data timerz9@tampered\n")

        val manager = AdbKeyManager(context)
        val info = manager.ensure()

        // Verify public key was accurately derived from the genuine private key
        val expectedBase64 = AdbPublicKey.base64(pair.public as java.security.interfaces.RSAPublicKey)
        val expectedEncoded = AdbPublicKey.encode(pair.public as java.security.interfaces.RSAPublicKey)
        assertEquals(expectedBase64, info.base64)
        assertEquals(AdbPublicKey.md5Fingerprint(expectedEncoded), info.md5Fingerprint)
        assertEquals(AdbPublicKey.sha256Fingerprint(expectedEncoded), info.sha256Fingerprint)

        // Verify backupFile was repaired to match genuine public key
        assertTrue(pubFile.readText().startsWith(expectedBase64))

        // Verify keyStore alias was NOT created (existing software key preserved without clobbering)
        if (store != null) {
            assertFalse(store.containsAlias("timerz9_adb_key"))
        }
    }
}
