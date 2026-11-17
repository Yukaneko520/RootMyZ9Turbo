package com.timerz9turbo.app.adb

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicLong

internal data class AdbShellResult(val exitCode: Int, val output: String)

/**
 * Minimal ADB host implementation for the loopback adbd. Shell (v1) execution
 * is supported over local TCP.
 */
internal class AdbClient(
    private val port: Int = 5555,
    private val host: String = "127.0.0.1",
    private val authenticator: AdbAuthenticator?,
    private val connectTimeoutMs: Int = 3_000,
    private val defaultReadTimeoutMs: Int = 30_000,
    /** Send the public key so system_server can show the authorization prompt. */
    private val requestAuthorization: Boolean = false,
) : Closeable {
    private var socket: Socket? = null
    private var input: DataInputStream? = null
    private var output: DataOutputStream? = null
    private var maxPayload = AdbProtocol.MAX_PAYLOAD
    private var nextLocalId = 1
    private val markerSequence = AtomicLong()

    fun connect() {
        check(socket == null) { "ADB client is already connected" }
        val key = authenticator ?: throw AdbKeyUnavailableException()
        val newSocket = Socket()
        var sentPublicKey = false
        var attempts = 0
        try {
            newSocket.connect(InetSocketAddress(host, port), connectTimeoutMs)
            newSocket.tcpNoDelay = true
            newSocket.soTimeout = defaultReadTimeoutMs
            val newInput = DataInputStream(newSocket.getInputStream().buffered())
            val newOutput = DataOutputStream(newSocket.getOutputStream().buffered())
            socket = newSocket
            input = newInput
            output = newOutput

            val banner = "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,abb_exec,remount_shell,track_app"
                .toByteArray(StandardCharsets.UTF_8)
            writePacket(AdbProtocol.A_CNXN, AdbProtocol.VERSION, AdbProtocol.MAX_PAYLOAD, banner)
            while (true) {
                val packet = readPacket()
                when (packet.command) {
                    AdbProtocol.A_AUTH -> {
                        if (packet.arg0 != AdbProtocol.AUTH_TOKEN) {
                            throw AdbProtocolException("Unexpected AUTH type ${packet.arg0}")
                        }
                        if (sentPublicKey) throw AdbUnauthorizedException()
                        attempts++
                        val publicKey = if (requestAuthorization) key.publicKeyLine() else null
                        if (attempts >= 2 && publicKey != null) {
                            // The signature was rejected, so ask system_server for
                            // the authorize prompt instead of writing adb_keys.
                            sentPublicKey = true
                            val payload = (publicKey + "\u0000").toByteArray(StandardCharsets.UTF_8)
                            writePacket(AdbProtocol.A_AUTH, AdbProtocol.AUTH_RSAPUBLICKEY, 0, payload)
                        } else if (attempts >= 2) {
                            // The single key's signature was rejected and we are not requesting an auth prompt.
                            throw AdbUnauthorizedException()
                        } else {
                            val signature = try {
                                key.signToken(packet.payload)
                            } catch (error: AdbException) {
                                throw error
                            } catch (error: Exception) {
                                throw AdbKeyUnavailableException("Cannot sign the ADB token: ${error.message}")
                            }
                            writePacket(AdbProtocol.A_AUTH, AdbProtocol.AUTH_SIGNATURE, 0, signature)
                        }
                    }

                    AdbProtocol.A_CNXN -> {
                        if (packet.arg1 >= 4096) maxPayload = minOf(maxPayload, packet.arg1)
                        return
                    }

                    AdbProtocol.A_STLS ->
                        throw AdbProtocolException("ADB TLS is not supported on the local 5555 transport")

                    else -> Unit // Ignore optional banners/acks during the handshake.
                }
            }
        } catch (error: Throwable) {
            close()
            when (error) {
                is AdbException -> throw error
                // After receiving an auth token, EOF or a socket timeout means
                // the device rejected our signature or authorization was cancelled.
                is IOException -> if (sentPublicKey || attempts > 0) {
                    throw AdbUnauthorizedException()
                } else {
                    throw AdbProtocolException("ADB handshake failed: ${error.message}")
                }

                else -> throw error
            }
        }
    }

    fun shell(
        command: String,
        timeoutMs: Int = defaultReadTimeoutMs,
        onLine: ((String) -> Unit)? = null,
    ): String {
        require(!command.contains('\u0000')) { "ADB shell command contains NUL" }
        val activeSocket = socket ?: throw AdbProtocolException("ADB client is not connected")
        val previousTimeout = activeSocket.soTimeout
        if (timeoutMs > 0) activeSocket.soTimeout = timeoutMs + 5_000
        try {
            val (localId, remoteId) = openService("shell:$command")
            return readService(localId, remoteId, onLine)
        } finally {
            if (timeoutMs > 0) runCatching { activeSocket.soTimeout = previousTimeout }
        }
    }

    fun exec(command: String, timeoutMs: Int = defaultReadTimeoutMs): AdbShellResult {
        val marker = "__TZ9_RC_${markerSequence.incrementAndGet()}__"
        val script = "$command\n__tz9_rc=\$?\nprintf '\\n${marker}%s\\n' \"\$__tz9_rc\""
        val output = shell(script, timeoutMs)
        val pattern = Regex("(?m)^${Regex.escape(marker)}(-?\\d+)\\s*$")
        val match = pattern.findAll(output).lastOrNull()
        val code = match?.groupValues?.get(1)?.toIntOrNull() ?: -1
        val cleaned = if (match == null) output else output.removeRange(match.range).trimEnd('\r', '\n')
        return AdbShellResult(code, cleaned)
    }

    override fun close() {
        runCatching { socket?.close() }
        socket = null
        input = null
        output = null
    }

    private fun writePacket(command: Int, arg0: Int = 0, arg1: Int = 0, payload: ByteArray = ByteArray(0)) {
        val out = output ?: throw AdbProtocolException("ADB client is not connected")
        AdbProtocol.writePacket(out, command, arg0, arg1, payload)
    }

    private fun readPacket(): AdbPacket = AdbProtocol.readPacket(
        input ?: throw AdbProtocolException("ADB client is not connected"),
    )

    private fun openService(service: String): Pair<Int, Int> {
        require(!service.contains('\u0000')) { "ADB service contains NUL" }
        val localId = nextLocalId++
        val payload = service.toByteArray(StandardCharsets.UTF_8) + byteArrayOf(0)
        writePacket(AdbProtocol.A_OPEN, localId, 0, payload)
        while (true) {
            val packet = readPacket()
            // Packets for streams we already closed (including their final
            // CLSE) must be ignored, otherwise a late close for the previous
            // service would abort the new one.
            if (packet.arg1 != localId) continue
            when (packet.command) {
                AdbProtocol.A_OKAY -> return localId to packet.arg0
                AdbProtocol.A_CLSE -> throw AdbProtocolException("ADB service closed before it opened")
                AdbProtocol.A_WRTE -> acknowledge(packet, localId)
                else -> Unit
            }
        }
    }

    private fun readService(localId: Int, remoteId: Int, onLine: ((String) -> Unit)?): String {
        val all = ByteArrayOutputStream()
        val lineSink = onLine?.let(::LineSink)
        while (true) {
            val packet = readPacket()
            if (packet.arg1 != localId) continue
            when (packet.command) {
                AdbProtocol.A_WRTE -> {
                    acknowledge(packet, localId)
                    if (packet.payload.isNotEmpty()) {
                        all.write(packet.payload)
                        lineSink?.feed(packet.payload)
                    }
                }

                AdbProtocol.A_CLSE -> {
                    lineSink?.finish()
                    return all.toString(StandardCharsets.UTF_8.name())
                }

                AdbProtocol.A_OKAY -> Unit
                else -> Unit
            }
        }
    }

    private fun acknowledge(packet: AdbPacket, localId: Int) {
        if (packet.arg1 == localId) writePacket(AdbProtocol.A_OKAY, packet.arg0, localId)
    }

    private class LineSink(private val onLine: (String) -> Unit) {
        private val pending = ByteArrayOutputStream()

        fun feed(data: ByteArray) {
            pending.write(data)
            val bytes = pending.toByteArray()
            var start = 0
            for (index in bytes.indices) {
                if (bytes[index] == '\n'.code.toByte()) {
                    emit(bytes, start, index - start)
                    start = index + 1
                }
            }
            pending.reset()
            if (start < bytes.size) pending.write(bytes, start, bytes.size - start)
        }

        fun finish() {
            if (pending.size() > 0) {
                emit(pending.toByteArray(), 0, pending.size())
                pending.reset()
            }
        }

        private fun emit(bytes: ByteArray, offset: Int, length: Int) {
            val line = String(bytes, offset, length, StandardCharsets.UTF_8).trimEnd('\r')
            onLine(line)
        }
    }
}

/** TCP probe used to verify that adbd closed its loopback port after rooting. */
internal fun adbPortOpen(port: Int = 5555, timeoutMs: Int = 600): Boolean = runCatching {
    Socket().use { socket ->
        socket.connect(InetSocketAddress("127.0.0.1", port), timeoutMs)
    }
    true
}.getOrDefault(false)
