package org.miga.android

import org.miga.core.DnsParser
import org.miga.core.DnsRouting
import org.miga.core.MultiTunnelEngine
import java.io.Closeable
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/** Uses Android's TCP stack through the VPN TUN; the engine pins its source port to one server. */
class AuxiliaryDnsTcpClient(private val engine: MultiTunnelEngine) : Closeable {
    private val lock = Any()
    private val sessions = HashMap<Socket, Thread>()
    private var closed = false
    private val vpnAddress = InetAddress.getByAddress(byteArrayOf(10, 254.toByte(), 83, 2))
    private val dnsAddress = InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1))

    fun submit(query: DnsRouting.TcpQuery) {
        val socket = Socket()
        val worker = Thread({ run(query, socket) }, "miga-aux-dns-tcp")
        synchronized(lock) {
            if (closed || sessions.size >= 16) { socket.close(); return }
            sessions[socket] = worker
        }
        worker.start()
    }

    private fun run(query: DnsRouting.TcpQuery, socket: Socket) {
        var port = 0
        var registered = false
        try {
            socket.soTimeout = 5_000
            socket.bind(InetSocketAddress(vpnAddress, 0))
            port = socket.localPort
            registered = engine.registerAuxiliaryDnsPort(port, query.profileId, query.generation)
            if (!registered || synchronized(lock) { closed }) return
            socket.connect(InetSocketAddress(dnsAddress, 53), 5_000)
            if (!engine.auxiliaryDnsPortObserved(port, query.profileId, query.generation)) return
            val output = socket.getOutputStream()
            output.write(query.message.size ushr 8)
            output.write(query.message.size)
            output.write(query.message)
            output.flush()
            val input = DataInputStream(socket.getInputStream())
            val length = input.readUnsignedShort()
            if (length !in 12..DnsParser.MAX_BYTES) return
            val answer = ByteArray(length)
            input.readFully(answer)
            if (!synchronized(lock) { closed }) engine.auxiliaryDnsAnswer(query, answer)
        } catch (_: Exception) {
            // A failed auxiliary lookup leaves the observed primary address denied.
        } finally {
            if (registered) engine.unregisterAuxiliaryDnsPort(port, query.profileId, query.generation)
            socket.close()
            synchronized(lock) { sessions.remove(socket) }
        }
    }

    override fun close() {
        val workers = synchronized(lock) {
            if (closed) return
            closed = true
            sessions.toMap()
        }
        workers.keys.forEach { it.close() }
        workers.values.forEach { if (it !== Thread.currentThread()) it.join(1_500) }
    }
}
