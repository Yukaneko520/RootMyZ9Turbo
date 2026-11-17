package com.timerz9turbo.app.adb

import com.timerz9turbo.app.domain.model.AdbLinkStatus
import com.timerz9turbo.app.domain.model.AdbSetupSnapshot
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
import org.junit.Test

class AdbAuthorizeHandshakeTest {
    private class FakeAuthenticator : AdbAuthenticator {
        override fun signToken(token: ByteArray): ByteArray = byteArrayOf(0x5a)
        override fun publicKeyLine(): String = "QUJD timerz9@device"
    }

    private data class ServerCapture(val publicKey: String?, val signatures: Int)

    @Test
    fun `second token sends the public key when authorization is requested`() {
        val capture = runServer(requestAuthorization = true, tokenCount = 2)
        assertEquals("QUJD timerz9@device\u0000", capture.publicKey)
        assertEquals(1, capture.signatures)
    }

    @Test
    fun `status handshake accepts connection on single signature`() {
        val capture = runServer(requestAuthorization = false, tokenCount = 1)
        assertNull(capture.publicKey)
        assertEquals(1, capture.signatures)
    }

    @Test(expected = AdbUnauthorizedException::class)
    fun `status handshake fails fast with unauthorized when server sends second challenge`() {
        runServer(requestAuthorization = false, tokenCount = 2)
    }

    @Test(expected = AdbUnauthorizedException::class)
    fun `server disconnect after auth token challenge throws unauthorized exception`() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                executor.submit {
                    server.accept().use { socket ->
                        val input = DataInputStream(socket.getInputStream())
                        val output = DataOutputStream(socket.getOutputStream())
                        AdbProtocol.readPacket(input) // CNXN
                        AdbProtocol.writePacket(output, AdbProtocol.A_AUTH, AdbProtocol.AUTH_TOKEN, 0, ByteArray(20))
                        AdbProtocol.readPacket(input) // SIGNATURE
                        // Server closes socket because signature was rejected
                        socket.close()
                    }
                }
                AdbClient(
                    port = server.localPort,
                    authenticator = FakeAuthenticator(),
                    connectTimeoutMs = 2_000,
                    defaultReadTimeoutMs = 5_000,
                    requestAuthorization = false,
                ).use { it.connect() }
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test(expected = AdbUnauthorizedException::class)
    fun `server disconnect after RSAPUBLICKEY throws unauthorized exception`() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                executor.submit {
                    server.accept().use { socket ->
                        val input = DataInputStream(socket.getInputStream())
                        val output = DataOutputStream(socket.getOutputStream())
                        AdbProtocol.readPacket(input) // CNXN
                        // First challenge -> signature
                        AdbProtocol.writePacket(output, AdbProtocol.A_AUTH, AdbProtocol.AUTH_TOKEN, 0, ByteArray(20))
                        AdbProtocol.readPacket(input)
                        // Second challenge -> public key
                        AdbProtocol.writePacket(output, AdbProtocol.A_AUTH, AdbProtocol.AUTH_TOKEN, 0, ByteArray(20))
                        AdbProtocol.readPacket(input)
                        // User clicked cancel / dialog dismissed -> adbd closes socket
                        socket.close()
                    }
                }
                AdbClient(
                    port = server.localPort,
                    authenticator = FakeAuthenticator(),
                    connectTimeoutMs = 2_000,
                    defaultReadTimeoutMs = 5_000,
                    requestAuthorization = true,
                ).use { it.connect() }
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test
    fun `exec parses command output and exit code correctly`() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                executor.submit {
                    server.accept().use { socket ->
                        val input = DataInputStream(socket.getInputStream())
                        val output = DataOutputStream(socket.getOutputStream())
                        AdbProtocol.readPacket(input) // CNXN
                        AdbProtocol.writePacket(output, AdbProtocol.A_CNXN, AdbProtocol.VERSION, AdbProtocol.MAX_PAYLOAD, "device::".toByteArray())
                        val open = AdbProtocol.readPacket(input) // OPEN
                        val localId = open.arg0
                        val remoteId = 100
                        AdbProtocol.writePacket(output, AdbProtocol.A_OKAY, remoteId, localId)
                        val shellResponse = "uid=2000(shell) gid=2000(shell)\r\nSeccomp: 2\r\n"
                        val script = String(open.payload, StandardCharsets.UTF_8)
                        val markerMatch = Regex("__TZ9_RC_\\d+__").find(script)
                        val marker = markerMatch?.value ?: "__TZ9_RC_1__"
                        val fullResponse = "$shellResponse\r\n${marker}0\r\n"
                        AdbProtocol.writePacket(output, AdbProtocol.A_WRTE, remoteId, localId, fullResponse.toByteArray(StandardCharsets.UTF_8))
                        AdbProtocol.readPacket(input) // OKAY ack
                        AdbProtocol.writePacket(output, AdbProtocol.A_CLSE, remoteId, localId)
                    }
                }
                AdbClient(
                    port = server.localPort,
                    authenticator = FakeAuthenticator(),
                    connectTimeoutMs = 2_000,
                    defaultReadTimeoutMs = 5_000,
                    requestAuthorization = false,
                ).use { client ->
                    client.connect()
                    val result = client.exec("id; grep -E '^Seccomp:' /proc/self/status")
                    assertEquals(0, result.exitCode)
                    assertTrue(result.output.contains("uid=2000(shell)"))
                    assertTrue(result.output.contains("Seccomp: 2"))
                    assertFalse(result.output.contains("__TZ9_RC_"))
                }
            } finally {
                executor.shutdownNow()
            }
        }
    }

    private fun runServer(requestAuthorization: Boolean, tokenCount: Int): ServerCapture =
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                val future = executor.submit<ServerCapture> {
                    server.accept().use { socket ->
                        socket.soTimeout = 5_000
                        val input = DataInputStream(socket.getInputStream())
                        val output = DataOutputStream(socket.getOutputStream())
                        assertEquals(AdbProtocol.A_CNXN, AdbProtocol.readPacket(input).command)

                        var signatures = 0
                        var publicKey: String? = null
                        repeat(tokenCount) {
                            AdbProtocol.writePacket(
                                output,
                                AdbProtocol.A_AUTH,
                                AdbProtocol.AUTH_TOKEN,
                                0,
                                ByteArray(20) { it.toByte() },
                            )
                            val response = AdbProtocol.readPacket(input)
                            assertEquals(AdbProtocol.A_AUTH, response.command)
                            when (response.arg0) {
                                AdbProtocol.AUTH_SIGNATURE -> signatures++
                                AdbProtocol.AUTH_RSAPUBLICKEY ->
                                    publicKey = String(response.payload, StandardCharsets.UTF_8)
                                else -> error("unexpected AUTH type ${response.arg0}")
                            }
                        }
                        AdbProtocol.writePacket(
                            output,
                            AdbProtocol.A_CNXN,
                            AdbProtocol.VERSION,
                            AdbProtocol.MAX_PAYLOAD,
                            "device::".toByteArray(StandardCharsets.UTF_8),
                        )
                        ServerCapture(publicKey, signatures)
                    }
                }
                AdbClient(
                    port = server.localPort,
                    authenticator = FakeAuthenticator(),
                    connectTimeoutMs = 2_000,
                    defaultReadTimeoutMs = 5_000,
                    requestAuthorization = requestAuthorization,
                ).use { it.connect() }
                future.get(10, TimeUnit.SECONDS)
            } finally {
                executor.shutdownNow()
            }
        }
}

class AdbSetupSnapshotKeyTest {
    @Test
    fun `ready link proves the key without root`() {
        assertTrue(AdbSetupSnapshot(keyFingerprint = "AA", linkStatus = AdbLinkStatus.READY).keyOk)
    }

    @Test
    fun `installed key still needs a fingerprint`() {
        assertFalse(AdbSetupSnapshot(adbKeyInstalled = true).keyOk)
        assertTrue(AdbSetupSnapshot(keyFingerprint = "AA", adbKeyInstalled = true).keyOk)
    }

    @Test
    fun `unauthorized key without root is not ok`() {
        assertFalse(
            AdbSetupSnapshot(keyFingerprint = "AA", linkStatus = AdbLinkStatus.UNAUTHORIZED).keyOk,
        )
    }

    @Test
    fun `unauthorized link overrides stale installed key`() {
        assertFalse(
            AdbSetupSnapshot(
                keyFingerprint = "AA",
                adbKeyInstalled = true,
                linkStatus = AdbLinkStatus.UNAUTHORIZED,
            ).keyOk,
        )
    }

    @Test
    fun `persisted key authorization marks key ok when link is not unauthorized`() {
        assertTrue(
            AdbSetupSnapshot(
                keyFingerprint = "AA",
                adbKeyAuthorized = true,
                linkStatus = AdbLinkStatus.UNREACHABLE,
            ).keyOk,
        )
        assertFalse(
            AdbSetupSnapshot(
                keyFingerprint = "AA",
                adbKeyAuthorized = true,
                linkStatus = AdbLinkStatus.UNAUTHORIZED,
            ).keyOk,
        )
        assertFalse(
            AdbSetupSnapshot(
                keyFingerprint = "AA",
                adbKeyAuthorized = true,
                keyRejected = true,
            ).keyOk,
        )
        assertFalse(
            AdbSetupSnapshot(
                adbKeyAuthorized = true,
            ).keyOk,
        )
    }

    @Test
    fun `setupComplete requires portOk, servicePortEmpty, and keyOk`() {
        val ready = AdbSetupSnapshot(
            persistPort = "5555",
            servicePort = null,
            keyFingerprint = "AA",
            adbKeyInstalled = true,
        )
        assertTrue(ready.setupComplete)

        val dirtyService = ready.copy(servicePort = "5555")
        assertFalse(dirtyService.servicePortEmpty)
        assertFalse(dirtyService.setupComplete)

        val wrongPort = ready.copy(persistPort = "5556")
        assertFalse(wrongPort.portOk)
        assertFalse(wrongPort.setupComplete)

        val missingKey = ready.copy(keyFingerprint = null)
        assertFalse(missingKey.keyOk)
        assertFalse(missingKey.setupComplete)
    }

    @Test
    fun `token signature with sha1 digest info verifies correctly`() {
        val keyPair = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val token = ByteArray(20) { (it * 7).toByte() }
        val digestInfoPayload = AdbPublicKey.sha1DigestInfo(token)

        val sig = java.security.Signature.getInstance("NONEwithRSA").apply {
            initSign(keyPair.private)
            update(digestInfoPayload)
        }.sign()

        val verified = java.security.Signature.getInstance("NONEwithRSA").apply {
            initVerify(keyPair.public)
            update(digestInfoPayload)
        }.verify(sig)
        assertTrue(verified)
    }

    @Test
    fun `deauthorization transition invalidates setup completion`() {
        // An authorized setup state:
        val authorized = AdbSetupSnapshot(
            persistPort = "5555",
            servicePort = null,
            keyFingerprint = "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00",
            keyFingerprintSha256 = "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00",
            adbKeyAuthorized = true,
            linkStatus = AdbLinkStatus.READY,
        )
        assertTrue(authorized.keyOk)
        assertTrue(authorized.setupComplete)

        // When authorization is revoked, link becomes UNAUTHORIZED:
        val revoked = authorized.copy(linkStatus = AdbLinkStatus.UNAUTHORIZED)
        assertFalse(revoked.keyOk)
        assertFalse(revoked.setupComplete)

        // When authorization is rejected, keyRejected is true:
        val rejected = authorized.copy(keyRejected = true, linkStatus = AdbLinkStatus.UNAUTHORIZED)
        assertFalse(rejected.keyOk)
        assertFalse(rejected.setupComplete)
    }

    @Test
    fun `unauthorized link status directly marks key not ok even if adbKeyAuthorized flag is true`() {
        val snapshot = AdbSetupSnapshot(
            keyFingerprint = "AA:BB:CC",
            adbKeyAuthorized = true,
            linkStatus = AdbLinkStatus.UNAUTHORIZED,
        )
        assertFalse(snapshot.keyOk)
        assertFalse(snapshot.setupComplete)
    }
}
