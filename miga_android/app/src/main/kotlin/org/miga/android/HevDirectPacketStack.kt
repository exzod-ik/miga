package org.miga.android

import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import hev.htproxy.TProxyService
import org.miga.core.DirectPacketStack
import org.miga.core.LocalDirectSocks
import org.miga.core.TunnelPacketLimits
import java.io.File
import java.io.FileDescriptor
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean

/** Feeds only DIRECT packets to lwIP over a private packet socket pair. Never reads the VPN TUN. */
class HevDirectPacketStack(
    service: VpnService,
    network: Network,
    private val onPacket: (ByteArray) -> Unit,
    private val onFailure: () -> Unit,
) : DirectPacketStack {
    private val stopped = AtomicBoolean(false)
    private val outbound = ArrayBlockingQueue<ByteArray>(128)
    private lateinit var appFd: ParcelFileDescriptor
    private lateinit var nativeFd: ParcelFileDescriptor
    private val random = SecureRandom()
    private val username = randomToken()
    private val password = randomToken()
    private lateinit var proxy: LocalDirectSocks
    private lateinit var config: File
    private var reader: Thread? = null
    private var writer: Thread? = null
    private var watchdog: Thread? = null

    init {
        try {
            val pair = packetSocketPair()
            appFd = pair[0]
            nativeFd = pair[1]
            proxy = LocalDirectSocks(ProtectedDirectSocketFactory(service, network), username, password)
            config = File.createTempFile("miga-direct-", ".yml", service.noBackupFilesDir)
            config.writeText("""
                tunnel:
                  mtu: ${TunnelPacketLimits.TUN_MTU}
                  ipv4: 10.254.83.2
                  icmp: 'off'
                socks5:
                  address: 127.0.0.1
                  port: ${proxy.port}
                  udp: 'udp'
                  username: '$username'
                  password: '$password'
                misc:
                  max-session-count: 32
                  tcp-buffer-size: 4096
                  udp-copy-buffer-nums: 8
                  connect-timeout: 10000
                  tcp-read-write-timeout: 60000
                  udp-read-write-timeout: 60000
                  log-level: warn
            """.trimIndent())
            Os.chmod(config.absolutePath, 0x180) // 0600
            check(TProxyService.TProxyStartService(config.absolutePath, nativeFd.fd)) {
                "Could not start DIRECT packet stack"
            }
            reader = Thread(::readPackets, "miga-direct-packets").also { it.start() }
            writer = Thread(::writePackets, "miga-direct-writer").also { it.start() }
            watchdog = Thread(::watchNative, "miga-direct-watchdog").also { it.start() }
        } catch (failure: Throwable) {
            close()
            if (failure is LinkageError) throw IllegalStateException("DIRECT native library could not load", failure)
            throw failure
        }
    }

    private fun randomToken(): String = ByteArray(24).also(random::nextBytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    /** The public PFD socket-pair helper is SOCK_STREAM, which loses IP-packet boundaries. */
    private fun packetSocketPair(): Array<ParcelFileDescriptor> {
        val first = FileDescriptor()
        val second = FileDescriptor()
        Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_SEQPACKET, 0, first, second)
        try {
            val left = ParcelFileDescriptor.dup(first)
            try { return arrayOf(left, ParcelFileDescriptor.dup(second)) }
            catch (failure: Throwable) { left.close(); throw failure }
        } finally {
            runCatching { Os.close(first) }
            runCatching { Os.close(second) }
        }
    }

    override fun send(packet: ByteArray): Boolean = !stopped.get() &&
        packet.isNotEmpty() && packet.size <= TunnelPacketLimits.MAX_INNER_PACKET &&
        outbound.offer(packet.copyOf())

    private fun readPackets() {
        val buffer = ByteArray(TunnelPacketLimits.MAX_INNER_PACKET + 1)
        try {
            while (!stopped.get()) {
                val count = Os.read(appFd.fileDescriptor, buffer, 0, buffer.size)
                if (count <= 0) throw IOException("DIRECT packet channel ended")
                if (count <= TunnelPacketLimits.MAX_INNER_PACKET) onPacket(buffer.copyOf(count))
            }
        } catch (_: Exception) { if (!stopped.get()) onFailure() }
    }

    private fun writePackets() {
        try {
            while (!stopped.get()) {
                val packet = outbound.take()
                val written = Os.write(appFd.fileDescriptor, packet, 0, packet.size)
                if (written != packet.size) throw IOException("Partial DIRECT packet write")
            }
        } catch (_: InterruptedException) { /* Stop. */ }
        catch (_: Exception) { if (!stopped.get()) onFailure() }
    }

    private fun watchNative() {
        try {
            while (!stopped.get()) {
                Thread.sleep(1_000)
                if (!TProxyService.TProxyIsRunning()) throw IOException("DIRECT stack stopped")
            }
        } catch (_: InterruptedException) { /* Stop. */ }
        catch (_: Exception) { if (!stopped.get()) onFailure() }
        catch (_: LinkageError) { if (!stopped.get()) onFailure() }
    }

    override fun close() {
        if (!stopped.compareAndSet(false, true)) return
        outbound.clear()
        writer?.interrupt()
        watchdog?.interrupt()
        if (::proxy.isInitialized) runCatching { proxy.close() }
        runCatching { TProxyService.TProxyStopService() }
        if (::appFd.isInitialized) runCatching { appFd.close() }
        if (::nativeFd.isInitialized) runCatching { nativeFd.close() }
        if (::config.isInitialized) runCatching { config.delete() }
        listOfNotNull(reader, writer, watchdog).forEach { thread ->
            if (thread !== Thread.currentThread()) runCatching { thread.join(1_500) }
        }
    }
}
