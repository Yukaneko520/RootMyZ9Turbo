package com.timerz9turbo.app.adb

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey

internal data class AdbKeyInfo(
    val base64: String,
    val line: String,
    val md5Fingerprint: String,
    val sha256Fingerprint: String,
) {
    val fingerprint: String get() = md5Fingerprint
}

/**
 * Secret half lives in AndroidKeyStore (TEE/StrongBox when the device provides
 * one). The public half is kept as an app-private backup; the setup flow sends
 * it through AUTH_RSAPUBLICKEY so system_server installs it in adb_keys.
 */
internal class AdbKeyManager(private val context: Context) : AdbAuthenticator {
    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "timerz9_adb_key"
        const val BACKUP_DIRECTORY = "adb"
        const val BACKUP_FILE = "adb_public_key.pub"
        const val SOFTWARE_PRIVATE_FILE = "adb_private_key.pk8"
    }

    private val backupFile = File(File(context.filesDir, BACKUP_DIRECTORY), BACKUP_FILE)
    private val softwareKeyFile = File(File(context.filesDir, BACKUP_DIRECTORY), SOFTWARE_PRIVATE_FILE)
    private var softwarePrivateKey: PrivateKey? = null
    private var cached: AdbKeyInfo? = null

    @Synchronized
    fun ensure(): AdbKeyInfo = cached ?: loadOrCreate(generate = true) ?: error("Cannot create ADB key")

    @Synchronized
    fun current(): AdbKeyInfo? = cached ?: loadOrCreate(generate = true)

    fun authenticator(): AdbAuthenticator? = if (current() == null) null else this

    override fun publicKeyLine(): String? = current()?.line

    override fun signToken(token: ByteArray): ByteArray {
        if (softwarePrivateKey == null && cached == null) {
            current()
        }
        val privKey = softwarePrivateKey
            ?: runCatching { keyStore()?.getKey(ALIAS, null) as? PrivateKey }.getOrNull()
            ?: throw AdbKeyUnavailableException("ADB private key is missing")
        // adbd verifies signatures using RSA_verify(NID_sha1, token, 20, sig, sig_len, key).
        // OpenSSL's RSA_verify expects the signed payload to be the ASN.1 SHA-1 DigestInfo
        // prepended to the 20-byte token, padded with PKCS#1 v1.5. NONEwithRSA over sha1DigestInfo
        // produces exactly this wire signature without hashing the token a second time.
        try {
            return Signature.getInstance("NONEwithRSA").run {
                initSign(privKey)
                update(AdbPublicKey.sha1DigestInfo(token))
                sign()
            }
        } catch (error: GeneralSecurityException) {
            throw AdbKeyUnavailableException("Cannot sign the ADB token: ${error.message}")
        }
    }

    private fun loadOrCreate(generate: Boolean): AdbKeyInfo? {
        val existingHardware = runCatching { loadFromHardware(generate = false) }.getOrNull()
        if (existingHardware != null) return existingHardware
        val existingSoftware = runCatching { loadFromSoftware(generate = false) }.getOrNull()
        if (existingSoftware != null) return existingSoftware
        if (!generate) return null
        val newHardware = runCatching { loadFromHardware(generate = true) }.getOrNull()
        if (newHardware != null) return newHardware
        return runCatching { loadFromSoftware(generate = true) }.getOrNull()
    }

    private fun loadFromHardware(generate: Boolean): AdbKeyInfo? {
        val store = keyStore() ?: return null
        if (!runCatching { store.containsAlias(ALIAS) }.getOrDefault(false)) {
            if (!generate) return null
            generateHardwareKey(store)
        }
        val certificate = runCatching { store.getCertificate(ALIAS) as? X509Certificate }.getOrNull()
        val publicKey = certificate?.publicKey as? RSAPublicKey ?: run {
            if (!generate) return null
            runCatching { store.deleteEntry(ALIAS) }
            generateHardwareKey(store)
            val replacement = runCatching { store.getCertificate(ALIAS) as? X509Certificate }.getOrNull()
            replacement?.publicKey as? RSAPublicKey ?: return null
        }
        // Verify the private key can actually perform raw NONEwithRSA signing.
        // Some TEEs or restricted Keystore providers forbid DIGEST_NONE; ADB daemon
        // requires NONEwithRSA because it verifies against the unhashed token.
        val privKey = runCatching { store.getKey(ALIAS, null) as? PrivateKey }.getOrNull() ?: return null
        val canSignRaw = runCatching {
            Signature.getInstance("NONEwithRSA").run {
                initSign(privKey)
                update(AdbPublicKey.sha1DigestInfo(ByteArray(20)))
                sign()
            }
        }.isSuccess
        if (!canSignRaw) {
            runCatching { store.deleteEntry(ALIAS) }
            return null
        }
        return remember(publicKey)
    }

    private fun loadFromSoftware(generate: Boolean): AdbKeyInfo? {
        if (softwareKeyFile.isFile) {
            try {
                val keyBytes = softwareKeyFile.readBytes()
                val kf = java.security.KeyFactory.getInstance("RSA")
                val priv = kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(keyBytes))
                softwarePrivateKey = priv
                if (priv is java.security.interfaces.RSAPrivateCrtKey) {
                    val pubSpec = java.security.spec.RSAPublicKeySpec(priv.modulus, priv.publicExponent)
                    val pubKey = kf.generatePublic(pubSpec) as RSAPublicKey
                    return remember(pubKey)
                }
                if (backupFile.isFile) {
                    val line = backupFile.readText().lineSequence().firstOrNull()?.trim().orEmpty()
                    val base64 = line.substringBefore(' ')
                    if (base64.isNotEmpty()) {
                        val encoded = java.util.Base64.getDecoder().decode(base64)
                        val info = AdbKeyInfo(
                            base64 = base64,
                            line = line,
                            md5Fingerprint = AdbPublicKey.md5Fingerprint(encoded),
                            sha256Fingerprint = AdbPublicKey.sha256Fingerprint(encoded),
                        )
                        cached = info
                        return info
                    }
                }
            } catch (_: Exception) {
            }
        }
        if (!generate) return null
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val pair = kpg.generateKeyPair()
        softwareKeyFile.parentFile?.mkdirs()
        softwareKeyFile.writeBytes(pair.private.encoded)
        softwarePrivateKey = pair.private
        return remember(pair.public as RSAPublicKey)
    }

    private fun remember(publicKey: RSAPublicKey): AdbKeyInfo {
        val encoded = AdbPublicKey.encode(publicKey)
        val host = "timerz9@${Build.DEVICE.orEmpty().replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "android" }}"
        val info = AdbKeyInfo(
            base64 = AdbPublicKey.base64(publicKey),
            line = "${AdbPublicKey.base64(publicKey)} $host",
            md5Fingerprint = AdbPublicKey.md5Fingerprint(encoded),
            sha256Fingerprint = AdbPublicKey.sha256Fingerprint(encoded),
        )
        val expected = info.line + "\n"
        if (!backupFile.isFile || backupFile.readText() != expected) {
            backupFile.parentFile?.mkdirs()
            backupFile.writeText(expected)
        }
        cached = info
        return info
    }

    private fun generateHardwareKey(store: KeyStore) {
        runCatching { store.deleteEntry(ALIAS) }
        try {
            generateKeyWithDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA1)
            return
        } catch (_: GeneralSecurityException) {
        }
        runCatching { store.deleteEntry(ALIAS) }
        generateKeyWithDigests(KeyProperties.DIGEST_NONE)
    }

    @SuppressLint("WrongConstant") // Values are documented KeyProperties.DIGEST_* constants.
    private fun generateKeyWithDigests(vararg digests: String) {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setKeySize(2048)
            .setDigests(*digests)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(false)
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    private fun keyStore(): KeyStore? = runCatching {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }.getOrNull()
}
