package org.miga.android

internal class DataPathHealth {
    private var generation = 0L
    private var unansweredSince: Long? = null
    private var lastSend = 0L
    private var deadline: Long? = null
    private var failures = 0

    fun sent(now: Long) {
        lastSend = now
        if (unansweredSince == null) unansweredSince = now
    }

    fun replied() {
        unansweredSince = null
        deadline = null
        failures = 0
    }

    fun check(now: Long, currentGeneration: Long, probe: () -> Unit): Boolean {
        if (generation != currentGeneration) {
            generation = currentGeneration
            deadline = null
            failures = 0
        }
        val since = unansweredSince ?: return false
        if (now - lastSend >= 60_000) {
            replied()
            return false
        }
        if (generation == 0L || now - since < 15_000) return false
        deadline?.let {
            if (now < it) return false
            if (++failures == 3) {
                replied()
                return true
            }
        }
        probe()
        deadline = now + 5_000
        return false
    }
}
