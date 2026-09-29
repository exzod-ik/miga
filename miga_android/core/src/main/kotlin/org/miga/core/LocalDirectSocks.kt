package org.miga.core

import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Implementations must protect and bind every returned socket before returning it. */
interface DirectSocketFactory {
    fun tcp(): Socket
    fun udp(): DatagramSocket
}

/** Loopback-only SOCKS5 upstream for a packet stack. No DNS or IPv6 forwarding. */
class LocalDirectSocks(
    private val sockets: DirectSocketFactory,
    private val username: String,
    private val password: String,
    private val maxSessions: Int = 32,
    private val idleMillis: Long = 60_000,
    private val allowLoopbackForTests: Boolean = false,
) : Closeable {
    init {
        require(username.length in 16..255 && password.length in 16..255)
        require(maxSessions in 1..256 && idleMillis in 1_000..600_000)
    }

    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val listener = ServerSocket(0, maxSessions, loopback)
    private val lock = Any()
    private val sessions = mutableSetOf<Session>()
    private val threads = mutableSetOf<Thread>()
    private var closed = false
    private val idleNanos = TimeUnit.MILLISECONDS.toNanos(idleMillis)
    private val watchPollMillis = minOf(1_000L, idleMillis / 4)
    val port: Int get() = listener.localPort
    val refused = AtomicLong()
    val tcpConnections = AtomicLong()
    val udpPackets = AtomicLong()

    private val tcpIdleWatch = launch("miga-direct-idle") { tcpIdleLoop() }

    init { launch("miga-direct-accept") { acceptLoop() } }

    private inner class Session(val control: Socket) : Closeable {
        private val owned = mutableListOf<Closeable>(control)
        private var done = false
        private var tcpLastProgressNanos: Long? = null

        fun own(resource: Closeable) = synchronized(this) {
            if (done) resource.close() else owned.add(resource)
        }

        fun startTcpIdleWatch() = synchronized(this) {
            if (!done) tcpLastProgressNanos = System.nanoTime()
        }

        fun noteTcpProgress() = synchronized(this) {
            if (!done) tcpLastProgressNanos = System.nanoTime()
        }

        fun closeIfTcpIdle(now: Long) = finishIf {
            tcpLastProgressNanos?.let { now - it >= idleNanos } == true
        }

        override fun close() = finishIf { true }

        private fun finishIf(shouldClose: () -> Boolean) {
            val resources = synchronized(this) {
                if (done || !shouldClose()) return
                done = true
                tcpLastProgressNanos = null
                owned.toList().also { owned.clear() }
            }
            resources.forEach { runCatching { it.close() } }
            synchronized(lock) { sessions.remove(this) }
        }
    }

    private fun tcpIdleLoop() {
        while (true) {
            val current = synchronized(lock) { if (closed) return else sessions.toList() }
            val now = System.nanoTime()
            current.forEach { it.closeIfTcpIdle(now) }
            try { Thread.sleep(watchPollMillis) }
            catch (_: InterruptedException) { return }
        }
    }

    private fun launch(name: String, body: () -> Unit): Thread {
        val thread = Thread({
            try { body() }
            finally { synchronized(lock) { threads.remove(Thread.currentThread()) } }
        }, name).apply { isDaemon = true }
        synchronized(lock) {
            if (closed) throw IOException("DIRECT proxy is closed")
            threads.add(thread)
        }
        thread.start()
        return thread
    }

    private fun acceptLoop() {
        while (true) {
            val client = try { listener.accept() } catch (_: SocketException) { return }
            val session = synchronized(lock) {
                if (closed || sessions.size >= maxSessions || threads.size >= maxSessions * 3 + 1) null
                else Session(client).also { sessions.add(it) }
            }
            if (session == null) { refused.incrementAndGet(); client.close(); continue }
            try { launch("miga-direct-session") { handle(session) } }
            catch (_: IOException) { session.close(); return }
        }
    }

    private fun handle(session: Session) {
        val client = session.control
        try {
            if (!client.inetAddress.isLoopbackAddress) return
            client.soTimeout = 10_000
            val input = DataInputStream(client.getInputStream())
            val output = client.getOutputStream()
            if (input.readUnsignedByte() != 5) return
            val methodCount = input.readUnsignedByte()
            if (methodCount !in 1..32) return
            val methods = ByteArray(methodCount).also(input::readFully)
            val supportsPassword = methods.any { it.toInt() == 2 }
            output.write(byteArrayOf(5, if (supportsPassword) 2 else 0xff.toByte()))
            if (!supportsPassword || input.readUnsignedByte() != 1) return
            val userLength = input.readUnsignedByte()
            val user = ByteArray(userLength).also(input::readFully).toString(Charsets.UTF_8)
            val passLength = input.readUnsignedByte()
            val pass = ByteArray(passLength).also(input::readFully).toString(Charsets.UTF_8)
            val authenticated = user == username && pass == password
            output.write(byteArrayOf(1, if (authenticated) 0 else 1))
            if (!authenticated || input.readUnsignedByte() != 5) return
            val command = input.readUnsignedByte()
            if (input.readUnsignedByte() != 0 || input.readUnsignedByte() != 1) {
                reply(output, 8, loopback, 0); return
            }
            val destination = InetAddress.getByAddress(ByteArray(4).also(input::readFully))
            val port = input.readUnsignedShort()
            when (command) {
                1 -> connectTcp(session, destination, port)
                3 -> associateUdp(session, destination, port)
                else -> reply(output, 7, loopback, 0)
            }
        } catch (_: IOException) {
            // Failed or cancelled SOCKS session.
        } finally { session.close() }
    }

    private fun connectTcp(session: Session, destination: InetAddress, port: Int) {
        val client = session.control
        val output = client.getOutputStream()
        if (!publicDestination(destination, port)) { reply(output, 2, loopback, 0); return }
        val remote = try {
            sockets.tcp().also { session.own(it); it.connect(InetSocketAddress(destination, port), 10_000) }
        } catch (_: IOException) { reply(output, 5, loopback, 0); return }
        tcpConnections.incrementAndGet()
        client.soTimeout = 0
        remote.soTimeout = 0
        reply(output, 0, loopback, 0)
        session.startTcpIdleWatch()
        val returner = launch("miga-direct-tcp-return") {
            pipe(session, remote, client)
        }
        pipe(session, client, remote)
        // A half-closed upload may still receive an arbitrarily long active response.
        returner.join()
    }

    private fun pipe(session: Session, from: Socket, to: Socket) {
        try {
            val source = from.getInputStream()
            val target = to.getOutputStream()
            val buffer = ByteArray(4096)
            while (true) {
                val count = source.read(buffer)
                if (count < 0) break
                target.write(buffer, 0, count)
                session.noteTcpProgress()
            }
            runCatching { to.shutdownOutput() }
        } catch (_: IOException) { session.close() }
    }

    private fun associateUdp(session: Session, requestedAddress: InetAddress, requestedPort: Int) {
        val client = session.control
        val output = client.getOutputStream()
        val relay = DatagramSocket(null).also { it.bind(InetSocketAddress(loopback, 0)); it.soTimeout = 1_000; session.own(it) }
        val remote = sockets.udp().also { it.soTimeout = 1_000; session.own(it) }
        reply(output, 0, loopback, relay.localPort)
        val caller = if (requestedAddress.isAnyLocalAddress || !requestedAddress.isLoopbackAddress) null
            else InetSocketAddress(requestedAddress, requestedPort).takeIf { requestedPort != 0 }
        val peer = AtomicReference(caller)
        val lastActivity = AtomicLong(System.nanoTime())
        val destinations = mutableSetOf<InetSocketAddress>()
        fun expired() = (System.nanoTime() - lastActivity.get()) / 1_000_000 >= idleMillis
        val outbound = launch("miga-direct-udp-out") {
            val bytes = ByteArray(2048)
            while (!expired()) {
                val packet = DatagramPacket(bytes, bytes.size)
                try { relay.receive(packet) } catch (_: SocketTimeoutException) { continue }
                catch (_: SocketException) { return@launch }
                val source = InetSocketAddress(packet.address, packet.port)
                if (!packet.address.isLoopbackAddress || (peer.get() != null && peer.get() != source)) continue
                if (packet.length < 10 || bytes[0].toInt() != 0 || bytes[1].toInt() != 0 ||
                    bytes[2].toInt() != 0 || bytes[3].toInt() != 1) continue
                val destination = InetAddress.getByAddress(bytes.copyOfRange(4, 8))
                val port = ((bytes[8].toInt() and 255) shl 8) or (bytes[9].toInt() and 255)
                if (!publicDestination(destination, port)) continue
                if (peer.get() == null) peer.compareAndSet(null, source)
                val permitted = synchronized(destinations) {
                    if (destinations.size >= 64 && InetSocketAddress(destination, port) !in destinations) false
                    else { destinations.add(InetSocketAddress(destination, port)); true }
                }
                if (!permitted) continue
                remote.send(DatagramPacket(bytes, 10, packet.length - 10, destination, port))
                lastActivity.set(System.nanoTime())
                udpPackets.incrementAndGet()
            }
        }
        val inbound = launch("miga-direct-udp-return") {
            val bytes = ByteArray(2048)
            while (!expired()) {
                val packet = DatagramPacket(bytes, bytes.size)
                try { remote.receive(packet) } catch (_: SocketTimeoutException) { continue }
                catch (_: SocketException) { return@launch }
                val target = peer.get() ?: continue
                val address = packet.address.address
                if (address.size != 4 || packet.length + 10 > bytes.size) continue
                if (synchronized(destinations) { InetSocketAddress(packet.address, packet.port) !in destinations }) continue
                val response = ByteArray(packet.length + 10)
                response[3] = 1
                address.copyInto(response, 4)
                response[8] = (packet.port ushr 8).toByte()
                response[9] = packet.port.toByte()
                bytes.copyInto(response, 10, 0, packet.length)
                relay.send(DatagramPacket(response, response.size, target))
                lastActivity.set(System.nanoTime())
            }
        }
        client.soTimeout = 1_000
        while (!expired()) {
            try { if (client.getInputStream().read() < 0) break }
            catch (_: SocketTimeoutException) { continue }
        }
        session.close()
        outbound.join(1_500)
        inbound.join(1_500)
    }

    private fun publicDestination(address: InetAddress, port: Int): Boolean = address is Inet4Address &&
        port in 1..65535 && (PublicRoutes.isPublic(address.address.fold(0) { acc, octet ->
            (acc shl 8) or (octet.toInt() and 255)
        }) || (allowLoopbackForTests && address.isLoopbackAddress))

    private fun reply(output: java.io.OutputStream, code: Int, address: InetAddress, port: Int) {
        output.write(byteArrayOf(5, code.toByte(), 0, 1) + address.address +
            byteArrayOf((port ushr 8).toByte(), port.toByte()))
    }

    override fun close() {
        val current = synchronized(lock) {
            if (closed) return
            closed = true
            sessions.toList()
        }
        listener.close()
        tcpIdleWatch.interrupt()
        current.forEach { it.close() }
        val workers = synchronized(lock) { threads.toList() }
        workers.forEach { if (it !== Thread.currentThread()) it.join(1_500) }
    }
}
