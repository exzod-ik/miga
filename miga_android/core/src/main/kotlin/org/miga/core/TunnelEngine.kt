package org.miga.core

import java.io.Closeable
import java.io.IOException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

interface PacketDevice : Closeable {
    /** Returns null after close. */
    fun read(): ByteArray?
    fun write(packet: ByteArray)
}

data class ReceivedDatagram(val bytes: ByteArray, val sourceIp: Int, val sourcePort: Int)

interface DatagramTransport : Closeable {
    fun receive(): ReceivedDatagram?
    fun send(bytes: ByteArray, destinationPort: Int)
}

data class TunnelStats(
    val sent: Long = 0, val received: Long = 0, val malformed: Long = 0,
    val fragments: Long = 0, val unknownEndpoint: Long = 0,
    val unknownFlow: Long = 0, val oversized: Long = 0,
    val queueDrops: Long = 0, val unansweredSinceMillis: Long = 0, val lastReplyMillis: Long = 0,
    val error: String? = null,
)

/** Two cancellable readers feed one bounded, single-owner packet processor. */
class TunnelEngine(
    private val device: PacketDevice,
    private val transport: DatagramTransport,
    private val codec: LegacyMigaCodec,
    private val serverIp: Int,
    private val firstPort: Int,
    private val lastPort: Int,
    private val portPicker: () -> Int,
    private val clock: Clock,
    private val onStats: (TunnelStats) -> Unit,
    queueCapacity: Int = 64,
    private val shutdownTimeoutMillis: Long = 2_000,
) : Closeable {
    init {
        require(firstPort in 1..65535 && lastPort in firstPort..65535)
        require(queueCapacity > 0 && shutdownTimeoutMillis > 0)
    }

    private val maxInnerSize = TunnelPacketLimits.MAX_INNER_PACKET

    private sealed interface Event {
        data class Out(val bytes: ByteArray) : Event
        data class In(val datagram: ReceivedDatagram) : Event
    }

    private val queue = ArrayBlockingQueue<Event>(queueCapacity)
    private enum class State { NEW, RUNNING, CLOSING, CLOSED, TIMED_OUT }
    private val lifecycleLock = Any()
    @Volatile private var state = State.NEW
    private val running = AtomicBoolean(false)
    private val failureSignaled = AtomicBoolean(false)
    private val cleanupDone = CountDownLatch(1)
    @Volatile var cleanupError: String? = null
        private set
    val cleanupCompleted: Boolean get() = state == State.CLOSED
    private val queueDrops = AtomicLong()
    private val flows = FlowTable(clock, 4096, 120_000)
    private var stats = TunnelStats()
    private var readers = emptyList<Thread>()
    private var worker: Thread? = null

    fun start() {
        synchronized(lifecycleLock) {
            check(state == State.NEW)
            state = State.RUNNING
            running.set(true)
            worker = Thread({ process() }, "miga-packets")
            readers = listOf(
                Thread({ readDevice() }, "miga-tun-reader"),
                Thread({ readTransport() }, "miga-udp-reader"),
            )
            worker!!.start()
            readers.forEach { it.start() }
        }
    }

    private fun readDevice() {
        try {
            while (running.get()) {
                val bytes = device.read()
                if (bytes == null) {
                    if (running.get()) fail("TUN reader", IOException("TUN read ended"))
                    break
                }
                if (!queue.offer(Event.Out(bytes))) queueDrops.incrementAndGet()
            }
        } catch (ex: Exception) { fail("TUN reader", ex) }
    }

    private fun readTransport() {
        try {
            while (running.get()) {
                val datagram = transport.receive()
                if (datagram == null) {
                    if (running.get()) fail("UDP reader", IOException("UDP receive ended"))
                    break
                }
                if (!queue.offer(Event.In(datagram))) queueDrops.incrementAndGet()
            }
        } catch (ex: Exception) { fail("UDP reader", ex) }
    }

    private fun process() {
        try {
            while (running.get()) {
                val event = queue.take()
                if (!running.get()) break
                when (event) {
                    is Event.Out -> outgoing(event.bytes)
                    is Event.In -> incoming(event.datagram)
                }
                stats = stats.copy(queueDrops = queueDrops.get())
                if (running.get()) onStats(stats)
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (ex: Exception) { fail("packet worker", ex) }
    }

    private fun outgoing(bytes: ByteArray) {
        if (bytes.size > maxInnerSize) { stats = stats.copy(oversized = stats.oversized + 1); return }
        val packet = Ipv4Packet.parse(bytes)
        if (packet == null) { reject(bytes); return }
        val maxMss = (maxInnerSize - packet.headerLength - packet.transportHeaderLength)
            .coerceAtMost(TunnelPacketLimits.TUNNEL_MAX_MSS)
        if (maxMss < 1) { stats = stats.copy(oversized = stats.oversized + 1); return }
        val payload = packet.clampMss(maxMss) ?: run { reject(bytes); return }
        val port = portPicker()
        require(port in firstPort..lastPort)
        flows.remember(FlowKey.from(packet).reverse(), 1)
        transport.send(codec.encode(payload, port), port)
        stats = stats.copy(sent = stats.sent + 1,
            unansweredSinceMillis = if (stats.unansweredSinceMillis == 0L) clock.elapsedMillis() else stats.unansweredSinceMillis)
    }

    private fun incoming(datagram: ReceivedDatagram) {
        if (datagram.sourceIp != serverIp || datagram.sourcePort !in firstPort..lastPort) {
            stats = stats.copy(unknownEndpoint = stats.unknownEndpoint + 1); return
        }
        if (datagram.bytes.isEmpty() || datagram.bytes.size > maxInnerSize) {
            stats = stats.copy(oversized = stats.oversized + 1); return
        }
        val decoded = codec.decode(datagram.bytes, datagram.sourcePort)
        val packet = ServerReplyPacket.parse(decoded)
        if (packet == null) { reject(decoded); return }
        if (!flows.contains(FlowKey.from(packet), 1)) {
            stats = stats.copy(unknownFlow = stats.unknownFlow + 1); return
        }
        val maxMss = (maxInnerSize - packet.headerLength - packet.transportHeaderLength)
            .coerceAtMost(TunnelPacketLimits.TUNNEL_MAX_MSS)
        if (maxMss < 1) { stats = stats.copy(oversized = stats.oversized + 1); return }
        val payload = packet.clampMss(maxMss) ?: run { reject(decoded); return }
        device.write(payload)
        stats = stats.copy(received = stats.received + 1, lastReplyMillis = clock.elapsedMillis(), unansweredSinceMillis = 0)
    }

    private fun reject(bytes: ByteArray) {
        val fragment = bytes.size >= 8 && (Ipv4Packet.u16(bytes, 6) and 0x3fff) != 0
        stats = if (fragment) stats.copy(fragments = stats.fragments + 1)
        else stats.copy(malformed = stats.malformed + 1)
    }

    private fun fail(source: String, ex: Exception) {
        if (!running.get() || !failureSignaled.compareAndSet(false, true)) return
        val reason = "$source ${ex.javaClass.simpleName}"
        var closeFailure: Exception? = null
        try { close() } catch (closeEx: Exception) { closeFailure = closeEx }
        val message = if (closeFailure == null) reason else "$reason; cleanup ${closeFailure.javaClass.simpleName}"
        try { onStats(stats.copy(error = message)) }
        catch (callbackEx: Exception) {
            cleanupError = listOfNotNull(cleanupError, "status callback ${callbackEx.javaClass.simpleName}").joinToString(", ")
        }
    }

    override fun close() {
        var threads = emptyList<Thread>()
        var alreadyClosing = false
        synchronized(lifecycleLock) {
            when (state) {
                State.CLOSED -> return
                State.TIMED_OUT -> throw IOException("Tunnel cleanup timed out")
                State.CLOSING -> alreadyClosing = true
                else -> {
                    state = State.CLOSING
                    running.set(false)
                    threads = readers + listOfNotNull(worker)
                }
            }
        }
        if (alreadyClosing) {
            if (!isEngineThread()) {
                val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(shutdownTimeoutMillis + 1_000)
                var interrupted = Thread.interrupted()
                try {
                    while (cleanupDone.count != 0L) {
                        val remaining = deadline - System.nanoTime()
                        if (remaining <= 0) throw IOException("Concurrent tunnel cleanup did not finish")
                        try { cleanupDone.await(remaining, TimeUnit.NANOSECONDS) }
                        catch (_: InterruptedException) { interrupted = true }
                    }
                } finally { if (interrupted) Thread.currentThread().interrupt() }
                if (state == State.TIMED_OUT) throw IOException("Tunnel cleanup timed out")
            }
            return
        }
        val errors = mutableListOf<Pair<String, Throwable>>()
        var timedOut = false
        var interrupted = Thread.interrupted() // Clear it until all peer joins are attempted.
        try {
            try { device.close() } catch (ex: Throwable) { errors.add("TUN" to ex) }
            try { transport.close() } catch (ex: Throwable) { errors.add("UDP" to ex) }
            threads.filter { it !== Thread.currentThread() }.forEach { it.interrupt() }
            queue.clear()
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(shutdownTimeoutMillis)
            for (thread in threads) {
                if (thread === Thread.currentThread() || !thread.isAlive) continue
                while (thread.isAlive) {
                    val remaining = deadline - System.nanoTime()
                    if (remaining <= 0) { timedOut = true; errors.add("thread" to IOException("Packet thread did not stop")); break }
                    try { thread.join(maxOf(1, TimeUnit.NANOSECONDS.toMillis(remaining))) }
                    catch (_: InterruptedException) { interrupted = true /* join clears the flag; keep waiting. */ }
                }
            }
        } finally {
            if (errors.isNotEmpty()) cleanupError = errors.joinToString(", ") { "${it.first} ${it.second.javaClass.simpleName}" }
            synchronized(lifecycleLock) { state = if (timedOut) State.TIMED_OUT else State.CLOSED }
            cleanupDone.countDown()
            if (interrupted) Thread.currentThread().interrupt()
        }
        if (errors.isNotEmpty()) throw IOException("Tunnel cleanup failed").also { failure ->
            errors.forEach { failure.addSuppressed(it.second) }
        }
    }

    private fun isEngineThread(): Boolean = Thread.currentThread() === worker || readers.any { it === Thread.currentThread() }

}
