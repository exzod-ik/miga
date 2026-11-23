package org.miga.android

import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import org.miga.core.DatagramTransport
import org.miga.core.ReceivedDatagram
import org.miga.core.SessionCodec

internal class ProtocolV2Transport(service: VpnService, network: Network, profile: ServerSession) : DatagramTransport, SessionCodec {
    private val data = DatagramSocket(null)
    private val control = DatagramSocket(null)
    private val receiveBuffer = ByteArray(65508)
    private val receivePacket = DatagramPacket(receiveBuffer, receiveBuffer.size)
    private val server = InetAddress.getByAddress(profile.serverAddress.split('.').map { it.toInt().toByte() }.toByteArray())
    private val lock = Any()
    private val serverIp = profile.serverIp
    private val health = DataPathHealth()
    private var handle = 0L
    @Volatile private var closed = false
    init {
        try {
            for (socket in listOf(data, control)) {
                socket.bind(InetSocketAddress(0))
                check(service.protect(socket)) { "VPN socket protection failed" }
                network.bindSocket(socket)
            }
            ParcelFileDescriptor.fromDatagramSocket(data).use { dataFd ->
                ParcelFileDescriptor.fromDatagramSocket(control).use { controlFd ->
                    handle = ProtocolV2Native.open(profile.invitation, profile.serverIp, dataFd.fd, controlFd.fd)
                }
            }
            check(handle != 0L) { "Cannot initialize protocol v2" }
        } catch (error: Throwable) { close(); throw error }
    }
    override val port: Int get() = synchronized(lock) { if (handle == 0L) 0 else ProtocolV2Native.port(handle) }
    override fun encode(packet: ByteArray, port: Int): ByteArray? = synchronized(lock) {
        if (handle == 0L) return@synchronized null
        if (ProtocolV2Native.sendStale(handle)) throw SocketException("Tunnel send activity expired")
        ProtocolV2Native.encode(handle, packet, port)
    }
    override fun decode(datagram: ByteArray, port: Int): ByteArray? = synchronized(lock) {
        if (handle == 0L) return@synchronized null
        val packet = ProtocolV2Native.decode(handle, datagram, port) ?: return@synchronized null
        health.replied()
        packet.takeUnless { it.isEmpty() }
    }
    override fun send(bytes: ByteArray, destinationPort: Int) {
        data.send(DatagramPacket(bytes, bytes.size, server, destinationPort))
        synchronized(lock) {
            if (handle != 0L) {
                ProtocolV2Native.dataSent(handle, destinationPort)
                health.sent(SystemClock.elapsedRealtime())
            }
        }
    }
    fun checkDataPath(now: Long): Boolean = synchronized(lock) {
        if (handle == 0L) return@synchronized false
        if (ProtocolV2Native.sendStale(handle)) return@synchronized true
        val generation = ProtocolV2Native.probeGeneration(handle)
        health.check(now, generation) { ProtocolV2Native.sendProbe(handle, generation, serverIp) }
    }
    override fun receive(): ReceivedDatagram? {
        val packet = receivePacket
        packet.length = receiveBuffer.size
        try { data.receive(packet) } catch (error: SocketException) { if (closed) return null else throw error }
        val address = packet.address.address
        val ip = if (address.size == 4) address.fold(0) { result, octet -> (result shl 8) or (octet.toInt() and 255) } else 0
        return ReceivedDatagram(receiveBuffer.copyOf(packet.length), ip, packet.port)
    }
    override fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
            if (handle != 0L) { ProtocolV2Native.close(handle); handle = 0L }
            data.close()
            control.close()
        }
    }
}
