package com.timerz9turbo.app.adb

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException

internal data class AdbPacket(
    val command: Int,
    val arg0: Int,
    val arg1: Int,
    val payload: ByteArray,
)

internal object AdbProtocol {
    // Command names are little-endian values from adb's protocol.h.
    const val A_SYNC = 0x434e5953
    const val A_CNXN = 0x4e584e43
    const val A_OPEN = 0x4e45504f
    const val A_OKAY = 0x59414b4f
    const val A_CLSE = 0x45534c43
    const val A_WRTE = 0x45545257
    const val A_AUTH = 0x48545541
    const val A_STLS = 0x534c5453

    const val AUTH_TOKEN = 1
    const val AUTH_SIGNATURE = 2
    const val AUTH_RSAPUBLICKEY = 3

    const val VERSION = 0x01000000
    const val MAX_PAYLOAD = 256 * 1024

    /** Refuse absurd lengths before allocating; adbd never sends more than this. */
    const val MAX_READ_PAYLOAD = 4 * 1024 * 1024

    /** 32-bit unsigned sum of payload bytes per AOSP ADB protocol. */
    fun checksum(payload: ByteArray): Int {
        var sum = 0
        for (b in payload) {
            sum += (b.toInt() and 0xFF)
        }
        return sum
    }

    fun writePacket(out: DataOutputStream, command: Int, arg0: Int = 0, arg1: Int = 0, payload: ByteArray = ByteArray(0)) {
        val checksum = checksum(payload)
        writeIntLe(out, command)
        writeIntLe(out, arg0)
        writeIntLe(out, arg1)
        writeIntLe(out, payload.size)
        writeIntLe(out, checksum)
        writeIntLe(out, command xor -1)
        if (payload.isNotEmpty()) out.write(payload)
        out.flush()
    }

    fun readPacket(input: DataInputStream): AdbPacket {
        val buffer = ByteArray(24)
        try {
            input.readFully(buffer)
        } catch (error: EOFException) {
            throw EOFException("ADB connection closed")
        }
        val command = readIntLe(buffer, 0)
        val arg0 = readIntLe(buffer, 4)
        val arg1 = readIntLe(buffer, 8)
        val length = readIntLe(buffer, 12)
        val checksum = readIntLe(buffer, 16)
        val magic = readIntLe(buffer, 20)
        if (magic != (command xor -1)) {
            throw IOException("ADB packet magic mismatch")
        }
        if (length < 0 || length > MAX_READ_PAYLOAD) {
            throw IOException("ADB payload length out of range: $length")
        }
        val payload = ByteArray(length)
        if (length > 0) {
            input.readFully(payload)
            val actual = checksum(payload)
            if (actual != checksum) throw IOException("ADB packet checksum mismatch")
        }
        return AdbPacket(command, arg0, arg1, payload)
    }

    fun writeIntLe(out: DataOutputStream, value: Int) {
        out.write(value and 0xff)
        out.write((value ushr 8) and 0xff)
        out.write((value ushr 16) and 0xff)
        out.write((value ushr 24) and 0xff)
    }

    fun readIntLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl 8) or
            ((bytes[offset + 2].toInt() and 0xff) shl 16) or
            ((bytes[offset + 3].toInt() and 0xff) shl 24)

    fun intLe(value: Int): ByteArray = byteArrayOf(
        (value and 0xff).toByte(),
        ((value ushr 8) and 0xff).toByte(),
        ((value ushr 16) and 0xff).toByte(),
        ((value ushr 24) and 0xff).toByte(),
    )

    fun commandName(packet: AdbPacket): String = when (packet.command) {
        A_SYNC -> "SYNC"
        A_CNXN -> "CNXN"
        A_OPEN -> "OPEN"
        A_OKAY -> "OKAY"
        A_CLSE -> "CLSE"
        A_WRTE -> "WRTE"
        A_AUTH -> "AUTH"
        A_STLS -> "STLS"
        else -> "0x%08x".format(packet.command)
    }
}

internal open class AdbException(message: String, cause: Throwable? = null) : IOException(message, cause)

internal class AdbUnauthorizedException : AdbException("ADB rejected the app key")

internal class AdbKeyUnavailableException(message: String = "ADB key is not available") : AdbException(message)

internal class AdbProtocolException(message: String) : AdbException(message)

internal interface AdbAuthenticator {
    fun signToken(token: ByteArray): ByteArray

    /** `<base64> <host>` for AUTH_RSAPUBLICKEY; null when the key is missing. */
    fun publicKeyLine(): String? = null
}
