package com.timerz9turbo.app.adb

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AdbProtocolTest {
    @Test
    fun `checksum calculation empty payload returns zero`() {
        assertEquals(0, AdbProtocol.checksum(ByteArray(0)))
    }

    @Test
    fun `checksum calculation treats bytes as unsigned`() {
        // -1 as signed byte is 0xFF (255)
        val payload = byteArrayOf(-1)
        assertEquals(255, AdbProtocol.checksum(payload))

        val multiPayload = byteArrayOf(0x01, 0x02, 0x03, -1)
        // 1 + 2 + 3 + 255 = 261
        assertEquals(261, AdbProtocol.checksum(multiPayload))
    }

    @Test
    fun `checksum matches expected sum for ascii payload`() {
        val payload = "host::features=shell_v2".toByteArray(Charsets.US_ASCII)
        val expectedSum = payload.fold(0) { acc, byte -> acc + (byte.toInt() and 0xFF) }
        assertEquals(expectedSum, AdbProtocol.checksum(payload))
    }

    @Test
    fun `packet round trip keeps command arguments and payload`() {
        val payload = "host::features=shell_v2".toByteArray()
        val bytes = ByteArrayOutputStream().also { stream ->
            DataOutputStream(stream).use {
                AdbProtocol.writePacket(it, AdbProtocol.A_CNXN, AdbProtocol.VERSION, AdbProtocol.MAX_PAYLOAD, payload)
            }
        }.toByteArray()

        val packet = AdbProtocol.readPacket(DataInputStream(ByteArrayInputStream(bytes)))
        assertEquals(AdbProtocol.A_CNXN, packet.command)
        assertEquals(AdbProtocol.VERSION, packet.arg0)
        assertEquals(AdbProtocol.MAX_PAYLOAD, packet.arg1)
        assertArrayEquals(payload, packet.payload)
        assertEquals("CNXN", AdbProtocol.commandName(packet))
    }

    @Test
    fun `readPacket correctly parses wire frame with standard adb checksum`() {
        val payload = byteArrayOf(0x10, 0x20, 0x30, -1) // 16 + 32 + 48 + 255 = 351 (0x0000015F)
        val command = AdbProtocol.A_AUTH
        val arg0 = AdbProtocol.AUTH_TOKEN
        val arg1 = 0
        val length = payload.size
        val checksum = 351
        val magic = command xor -1

        val buffer = ByteArray(24 + payload.size)
        // Little endian encoding:
        fun putIntLe(offset: Int, value: Int) {
            buffer[offset] = (value and 0xFF).toByte()
            buffer[offset + 1] = ((value ushr 8) and 0xFF).toByte()
            buffer[offset + 2] = ((value ushr 16) and 0xFF).toByte()
            buffer[offset + 3] = ((value ushr 24) and 0xFF).toByte()
        }
        putIntLe(0, command)
        putIntLe(4, arg0)
        putIntLe(8, arg1)
        putIntLe(12, length)
        putIntLe(16, checksum)
        putIntLe(20, magic)
        System.arraycopy(payload, 0, buffer, 24, payload.size)

        val packet = AdbProtocol.readPacket(DataInputStream(ByteArrayInputStream(buffer)))
        assertEquals(command, packet.command)
        assertEquals(arg0, packet.arg0)
        assertEquals(arg1, packet.arg1)
        assertArrayEquals(payload, packet.payload)
    }

    @Test(expected = IOException::class)
    fun `corrupted magic is rejected`() {
        val bytes = ByteArrayOutputStream().also { stream ->
            DataOutputStream(stream).use { AdbProtocol.writePacket(it, AdbProtocol.A_OKAY, 1, 2) }
        }.toByteArray()
        bytes[20] = (bytes[20].toInt() xor 0x7f).toByte()
        AdbProtocol.readPacket(DataInputStream(ByteArrayInputStream(bytes)))
    }

    @Test(expected = IOException::class)
    fun `corrupted payload checksum is rejected`() {
        val bytes = ByteArrayOutputStream().also { stream ->
            DataOutputStream(stream).use {
                AdbProtocol.writePacket(it, AdbProtocol.A_WRTE, 1, 2, "hello".toByteArray())
            }
        }.toByteArray()
        bytes[24] = (bytes[24].toInt() xor 0x01).toByte()
        AdbProtocol.readPacket(DataInputStream(ByteArrayInputStream(bytes)))
    }
}

class AdbPublicKeyTest {
    @Test
    fun `blob matches the adb RSAPublicKey format`() {
        val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val key = generator.generateKeyPair().public as RSAPublicKey
        val blob = AdbPublicKey.encode(key)
        assertEquals(524, blob.size)

        // android_pubkey.h RSAPublicKey: modulus_size_words is words (64 for 2048-bit), not bytes (256)
        val modulusWords = BigInteger(1, blob.copyOfRange(0, 4).reversedArray()).toInt()
        assertEquals(64, modulusWords)
        val length = modulusWords * 4
        assertEquals(256, length)

        val modulus = BigInteger(1, blob.copyOfRange(8, 8 + length).reversedArray())
        assertEquals(key.modulus, modulus)
        val expectedN0 = key.modulus.mod(BigInteger.ONE.shiftLeft(32))
            .modInverse(BigInteger.ONE.shiftLeft(32))
            .negate()
            .mod(BigInteger.ONE.shiftLeft(32))
        val actualN0 = BigInteger(1, blob.copyOfRange(4, 8).reversedArray())
        assertEquals(expectedN0, actualN0)
        val rr = BigInteger(1, blob.copyOfRange(8 + length, 8 + length * 2).reversedArray())
        val r = BigInteger.ONE.shiftLeft(length * 8)
        assertEquals(r.multiply(r).mod(key.modulus), rr)
        val exponent = BigInteger(1, blob.copyOfRange(8 + length * 2, blob.size).reversedArray())
        assertEquals(key.publicExponent, exponent)
    }

    @Test
    fun `fingerprint and host line are stable`() {
        val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val key = generator.generateKeyPair().public as RSAPublicKey
        val encoded = AdbPublicKey.encode(key)
        assertTrue(AdbPublicKey.md5Fingerprint(encoded).matches(Regex("([0-9A-F]{2}:){15}[0-9A-F]{2}")))
        assertTrue(AdbPublicKey.sha256Fingerprint(encoded).matches(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}")))
        assertEquals(AdbPublicKey.md5Fingerprint(encoded), AdbPublicKey.fingerprint(encoded))
        assertEquals(AdbPublicKey.base64(key) + " timerz9@test", AdbPublicKey.line(key, "timerz9@test"))
        assertEquals(
            java.util.Base64.getEncoder().encodeToString(encoded),
            AdbPublicKey.base64(key),
        )
    }

    @Test
    fun `md5 fingerprint matches 16 bytes hex format matching AdbDebuggingManager`() {
        val testBytes = "TimerZ9AdbKeyTestPayload".toByteArray(Charsets.UTF_8)
        val md5 = AdbPublicKey.md5Fingerprint(testBytes)
        val parts = md5.split(":")
        assertEquals(16, parts.size)
        assertTrue(parts.all { it.length == 2 && it.matches(Regex("[0-9A-F]{2}")) })

        val sha256 = AdbPublicKey.sha256Fingerprint(testBytes)
        val shaParts = sha256.split(":")
        assertEquals(32, shaParts.size)
        assertTrue(shaParts.all { it.length == 2 && it.matches(Regex("[0-9A-F]{2}")) })
    }

    @Test
    fun `fingerprint formatting is invariant under non-US default locale`() {
        val original = java.util.Locale.getDefault()
        try {
            java.util.Locale.setDefault(java.util.Locale.forLanguageTag("tr-TR"))
            val testBytes = byteArrayOf(0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f)
            val md5 = AdbPublicKey.md5Fingerprint(testBytes)
            assertTrue(md5.matches(Regex("([0-9A-F]{2}:){15}[0-9A-F]{2}")))
            val sha256 = AdbPublicKey.sha256Fingerprint(testBytes)
            assertTrue(sha256.matches(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}")))
        } finally {
            java.util.Locale.setDefault(original)
        }
    }
}
