package org.miga.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.first
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

private val Context.settingsDataStore by preferencesDataStore(name = "miga_settings")

enum class ThemeChoice {
    SYSTEM, LIGHT, DARK;
    companion object {
        fun fromStored(value: String?): ThemeChoice = entries.firstOrNull { it.name == value } ?: SYSTEM
    }
}

class ThemePreference(private val context: Context) {
    private val key = stringPreferencesKey("theme")
    val choice: Flow<ThemeChoice> = context.settingsDataStore.data.map { preferences ->
        ThemeChoice.fromStored(preferences[key])
    }
    suspend fun save(choice: ThemeChoice) { context.settingsDataStore.edit { it[key] = choice.name } }
}

class DataStoreSettings(private val context: Context) : SettingsStore {
    private val document = stringPreferencesKey("document")
    override suspend fun read(): String? = context.settingsDataStore.data.first()[document]
    override suspend fun write(value: String) {
        context.settingsDataStore.edit { it[document] = value }
    }
}

class KeystoreSecretStore(context: Context) : SecretStore by DispatchingSecretStore(KeystoreFiles(context))

private class KeystoreFiles(private val context: Context) : BlockingSecretStore {
    private val alias = "miga_profile_keys_v1"

    private fun directory(): File = File(context.noBackupFilesDir, "secrets")
        .also { check(it.isDirectory || it.mkdirs()) }

    private fun file(ref: String): File {
        require(UUID.fromString(ref).toString() == ref) { "Invalid secret reference" }
        return File(directory(), ref)
    }

    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
        val existing = store.getKey(alias, null) as? SecretKey
        if (existing != null) return existing
        if (!create) throw SecretUnavailable()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build())
        return generator.generateKey()
    }

    override fun put(ref: String, keys: SecretKeys) {
        require(keys.xor.size == 128 && keys.swap.size == 8) { "Invalid key length" }
        val target = file(ref)
        check(!target.exists()) { "Secret reference already exists" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key(true)) // Provider creates a fresh random IV.
        cipher.updateAAD(ref.toByteArray(Charsets.UTF_8))
        val ciphertext = cipher.doFinal(keys.xor + keys.swap)
        val iv = cipher.iv
        check(iv.size == 12) { "Unsupported nonce length" }
        val temporary = File.createTempFile("key-", ".tmp", directory())
        try {
            temporary.writeBytes(byteArrayOf(1) + iv + ciphertext)
            check(temporary.renameTo(target)) { "Could not save keys" }
        } finally { temporary.delete() }
    }

    override fun get(ref: String): SecretKeys {
        try {
            val data = file(ref).readBytes()
            if (data.size != 1 + 12 + 136 + 16 || data[0] != 1.toByte()) throw SecretUnavailable()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, data.copyOfRange(1, 13)))
            cipher.updateAAD(ref.toByteArray(Charsets.UTF_8))
            val plain = cipher.doFinal(data.copyOfRange(13, data.size))
            if (plain.size != 136) throw SecretUnavailable()
            return SecretKeys(plain.copyOfRange(0, 128), plain.copyOfRange(128, 136))
        } catch (_: Exception) { throw SecretUnavailable() }
    }

    override fun delete(ref: String) {
        val target = file(ref)
        check(!target.exists() || target.delete()) { "Could not delete old keys" }
    }
}
