package org.miga.android

import android.content.Context
import com.jcraft.jsch.JSch
import com.jcraft.jsch.UserInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.io.File
import kotlin.coroutines.EmptyCoroutineContext

internal data class RemoteServerSettings(val firstPort: Int, val lastPort: Int, val keys: SecretKeys)

internal class ServerConfigSsh(private val context: Context) {
    suspend fun fetch(address: String, username: String, password: String,
                      confirmHost: suspend (String) -> Boolean): RemoteServerSettings {
        require(username.isNotBlank() && password.isNotBlank()) { "Enter SSH login and password" }
        val parent = kotlin.coroutines.coroutineContext[Job]
        return withContext(Dispatchers.IO) {
            val knownHosts = File(context.filesDir, "ssh_known_hosts")
            if (!knownHosts.exists()) knownHosts.createNewFile()
            val jsch = JSch().apply { setKnownHosts(knownHosts.absolutePath) }
            val session = jsch.getSession(username.trim(), address, 22)
            session.setPassword(password.toByteArray(Charsets.UTF_8))
            session.timeout = 10_000
            session.setConfig("StrictHostKeyChecking", "ask")
            session.setConfig("PreferredAuthentications", "password")
            session.setUserInfo(object : UserInfo {
                override fun getPassword(): String? = null
                override fun getPassphrase(): String? = null
                override fun promptPassword(message: String?): Boolean = false
                override fun promptPassphrase(message: String?): Boolean = false
                override fun showMessage(message: String?) = Unit
                override fun promptYesNo(message: String?): Boolean = runBlocking(parent ?: EmptyCoroutineContext) {
                    if (parent?.isActive != true) false
                    else withTimeout(60_000) { confirmHost(message ?: "Confirm the SSH server key") }
                }
            })
            try {
                session.connect(10_000)
                val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
                try {
                    channel.setCommand("cat /etc/miga/config.json")
                    val input = channel.inputStream
                    channel.connect(10_000)
                    val json = input.bufferedReader(Charsets.UTF_8).use { reader ->
                        val content = StringBuilder()
                        val buffer = CharArray(4096)
                        while (true) {
                            val count = reader.read(buffer)
                            if (count < 0) break
                            require(content.length + count <= 65_536) { "Server configuration is too large" }
                            content.append(buffer, 0, count)
                        }
                        content.toString()
                    }
                    while (!channel.isClosed) kotlinx.coroutines.delay(25)
                    check(channel.exitStatus == 0) { "Cannot read /etc/miga/config.json" }
                    parse(json)
                } finally { channel.disconnect() }
            } catch (ex: CancellationException) { throw ex }
            finally { session.disconnect() }
        }
    }

    companion object {
        fun parse(json: String): RemoteServerSettings {
            val root = JSONObject(json)
            val ports = root.getJSONObject("client_ports")
            val encryption = root.getJSONObject("encryption")
            val first = ports.getInt("start")
            val last = ports.getInt("end")
            require(first in 1..65535 && last in first..65535) { "Invalid server UDP port range" }
            return RemoteServerSettings(first, last, SecretKeys(
                SessionValidator.keyBase64(encryption.getString("xor_key"), 128),
                SessionValidator.keyBase64(encryption.getString("swap_key"), 8)))
        }
    }
}
