package org.miga.android

import org.miga.core.PacketDevice
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Drain captured packets while no UDP transport exists; never replay stale flows. */
internal class PacketDropper(private val device: PacketDevice) : Closeable {
    private val running = AtomicBoolean(true)
    val dropped = AtomicLong()
    private val worker = Thread({
        try { while (running.get() && device.read() != null) dropped.incrementAndGet() }
        catch (_: Exception) { /* Closing the TUN duplicate cancels the read. */ }
    }, "miga-offline-drop")

    fun start() = worker.start()

    override fun close() {
        if (!running.compareAndSet(true, false)) return
        var failure: Throwable? = null
        try { device.close() } catch (ex: Throwable) { failure = ex }
        var interrupted = Thread.interrupted()
        try {
            val deadline = System.nanoTime() + 2_000_000_000L
            while (worker.isAlive) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) break
                try { worker.join(maxOf(1, remaining / 1_000_000L)) }
                catch (_: InterruptedException) { interrupted = true }
            }
        } finally { if (interrupted) Thread.currentThread().interrupt() }
        if (worker.isAlive) throw IllegalStateException("Offline packet reader did not stop", failure)
        if (failure != null) throw IllegalStateException("Offline packet reader close failed", failure)
    }
}
