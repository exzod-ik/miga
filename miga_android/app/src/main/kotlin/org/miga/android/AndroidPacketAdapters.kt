package org.miga.android

import android.net.Network
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import org.miga.core.TunnelPacketLimits
import org.miga.core.DatagramTransport
import org.miga.core.PacketDevice
import org.miga.core.ReceivedDatagram
import org.miga.core.ConnectionOwnerResolver
import org.miga.core.DirectSocketFactory
import org.miga.core.FlowKey
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class TunPacketDevice(private val descriptor: ParcelFileDescriptor) : PacketDevice {
    private val wake = ParcelFileDescriptor.createPipe()
    private val wakeRead = wake[0]
    private val wakeWrite = wake[1]
    private val closed = AtomicBoolean(false)
    private val operationsLock = Object()
    private var activeOperations = 0
    private val readBuffer = ByteArray(65535)

    override fun read(): ByteArray? {
        if (!enter()) return null
        try {
            while (!closed.get()) {
                if (!awaitReady(OsConstants.POLLIN)) continue
                try {
                    val count = Os.read(descriptor.fileDescriptor, readBuffer, 0, readBuffer.size)
                    if (count <= 0) throw IOException("TUN read ended")
                    return readBuffer.copyOf(count)
                } catch (ex: ErrnoException) {
                    if (ex.errno != OsConstants.EAGAIN && ex.errno != OsConstants.EINTR) throw ex
                }
            }
            return null
        } catch (ex: Exception) {
            if (closed.get()) return null
            throw ex
        } finally { leave() }
    }

    override fun write(packet: ByteArray) {
        if (!enter()) throw IOException("TUN is closed")
        try {
            while (!closed.get()) {
                try {
                    val count = Os.write(descriptor.fileDescriptor, packet, 0, packet.size)
                    if (count != packet.size) throw IOException("Partial TUN packet write")
                    return
                } catch (ex: ErrnoException) {
                    if (ex.errno != OsConstants.EAGAIN && ex.errno != OsConstants.EINTR) throw ex
                    if (ex.errno == OsConstants.EAGAIN) awaitReady(OsConstants.POLLOUT)
                }
            }
            throw IOException("TUN is closed")
        } finally { leave() }
    }

    /** A wake pipe cancels poll immediately; a finite timeout also bounds cancellation if signaling fails. */
    private fun awaitReady(events: Int): Boolean {
        val tunPoll = StructPollfd().apply { fd = descriptor.fileDescriptor; this.events = events.toShort() }
        val wakePoll = StructPollfd().apply { fd = wakeRead.fileDescriptor; this.events = OsConstants.POLLIN.toShort() }
        try { Os.poll(arrayOf(tunPoll, wakePoll), 1_000) }
        catch (ex: ErrnoException) {
            if (ex.errno == OsConstants.EINTR || closed.get()) return false
            throw ex
        }
        if (closed.get() || wakePoll.revents.toInt() != 0) return false
        val bad = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
        if (tunPoll.revents.toInt() and bad != 0) throw IOException("TUN descriptor failed")
        return tunPoll.revents.toInt() and events != 0
    }

    private fun enter(): Boolean = synchronized(operationsLock) {
        if (closed.get()) false else { activeOperations++; true }
    }

    private fun leave() = synchronized(operationsLock) {
        activeOperations--
        operationsLock.notifyAll()
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        val errors = mutableListOf<Throwable>()
        try { Os.write(wakeWrite.fileDescriptor, byteArrayOf(1), 0, 1) } catch (ex: Throwable) { errors.add(ex) }
        try { descriptor.close() } catch (ex: Throwable) { errors.add(ex) }
        try { wakeWrite.close() } catch (ex: Throwable) { errors.add(ex) }
        synchronized(operationsLock) {
            val deadline = System.nanoTime() + 1_500_000_000L
            while (activeOperations > 0) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) { errors.add(IOException("TUN operation did not stop")); break }
                try { operationsLock.wait(maxOf(1, remaining / 1_000_000L)) }
                catch (ex: InterruptedException) { Thread.currentThread().interrupt(); errors.add(ex); break }
            }
        }
        try { wakeRead.close() } catch (ex: Throwable) { errors.add(ex) }
        if (errors.isNotEmpty()) throw IOException("TUN close failed").also { failure -> errors.forEach { failure.addSuppressed(it) } }
    }
}

class AndroidConnectionOwnerResolver(private val manager: ConnectivityManager) : ConnectionOwnerResolver {
    override fun ownerUid(flow: FlowKey): Int = manager.getConnectionOwnerUid(flow.protocol,
        InetSocketAddress(flow.sourceIp.toAddress(), flow.sourcePort),
        InetSocketAddress(flow.destinationIp.toAddress(), flow.destinationPort))

    private fun Int.toAddress() = InetAddress.getByAddress(byteArrayOf(
        (this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), toByte()))
}

/** Every physical DIRECT socket is protected and bound before connect/send. */
class ProtectedDirectSocketFactory(private val service: VpnService, private val network: Network) : DirectSocketFactory {
    override fun tcp(): Socket = Socket().also { socket ->
        try {
            socket.receiveBufferSize = 64 * 1024
            socket.sendBufferSize = 64 * 1024
            check(service.protect(socket)) { "DIRECT TCP socket protection failed" }
            network.bindSocket(socket)
        } catch (ex: Exception) { socket.close(); throw ex }
    }

    override fun udp(): DatagramSocket = DatagramSocket(null).also { socket ->
        try {
            socket.bind(InetSocketAddress(0))
            socket.receiveBufferSize = 64 * 1024
            socket.sendBufferSize = 64 * 1024
            check(service.protect(socket)) { "DIRECT UDP socket protection failed" }
            network.bindSocket(socket)
        } catch (ex: Exception) { socket.close(); throw ex }
    }
}
