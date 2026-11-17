package com.timerz9turbo.app.adb

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * Android's adb public-key blob is a serialized `RSAPublicKey`:
 *   uint32 len, uint32 n0inv, len-byte modulus, len-byte rr, uint32 exponent
 * Integers are little-endian fields, the two bignums are big-endian bytes.
 * adbd base64-decodes that blob from adb_keys and from AUTH_RSAPUBLICKEY.
 */
internal object AdbPublicKey {
    private val TWO_32 = BigInteger.ONE.shiftLeft(32)
    private val SHA1_DIGEST_INFO = byteArrayOf(
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a,
        0x05, 0x00, 0x04, 0x14,
    )

    fun encode(key: RSAPublicKey): ByteArray {
        val modulus = key.modulus
        val length = (modulus.bitLength() + 7) / 8
        require(length in 128..1024) { "Unsupported ADB RSA key size: $length" }

        // adb serializes both bignums as little-endian byte arrays.
        val modulusBytes = fixedBytes(modulus, length).reversedArray()
        val r = BigInteger.ONE.shiftLeft(length * 8)
        val rr = r.multiply(r).mod(modulus)
        val rrBytes = fixedBytes(rr, length).reversedArray()
        val n0inv = modulus.mod(TWO_32).modInverse(TWO_32).negate().mod(TWO_32)

        // android_pubkey.h RSAPublicKey format:
        // uint32_t modulus_size_words: length in 32-bit words (64 for 2048-bit RSA)
        val modulusWords = length / 4
        return ByteBuffer.allocate(4 + 4 + length + length + 4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(modulusWords)
            .putInt(n0inv.toInt())
            .put(modulusBytes)
            .put(rrBytes)
            .putInt(key.publicExponent.toInt())
            .array()
    }

    fun base64(key: RSAPublicKey): String =
        Base64.getEncoder().encodeToString(encode(key))

    fun line(key: RSAPublicKey, host: String): String = "${base64(key)} $host"

    fun md5Fingerprint(encoded: ByteArray): String =
        MessageDigest.getInstance("MD5").digest(encoded)
            .joinToString(":") { "%02X".format(java.util.Locale.US, it) }

    fun sha256Fingerprint(encoded: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(encoded)
            .joinToString(":") { "%02X".format(java.util.Locale.US, it) }

    fun fingerprint(encoded: ByteArray): String = md5Fingerprint(encoded)

    fun sha1DigestInfo(token: ByteArray): ByteArray = SHA1_DIGEST_INFO + token

    private fun fixedBytes(value: BigInteger, length: Int): ByteArray {
        val raw = value.toByteArray()
        val withoutSign = if (raw.size > length) raw.copyOfRange(raw.size - length, raw.size) else raw
        return ByteArray(length).also { withoutSign.copyInto(it, length - withoutSign.size) }
    }
}
