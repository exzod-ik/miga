package org.miga.android

/** Activity callbacks and snapshot results are accepted only for the current Start request. */
internal class StartCoordinator {
    private var nextId = 0L
    private var activeId: Long? = null
    private val vpnResults = ArrayDeque<Long>()

    fun begin(): Long? {
        if (activeId != null) return null
        val id = ++nextId
        activeId = id
        return id
    }

    fun isCurrent(id: Long): Boolean = activeId == id

    suspend fun <T> prepare(id: Long, snapshot: suspend () -> T): T? {
        if (!isCurrent(id)) return null
        val result = snapshot()
        return result.takeIf { isCurrent(id) }
    }

    fun expectVpnResult(id: Long) { if (isCurrent(id)) vpnResults.addLast(id) }
    fun forgetVpnResult(id: Long) { vpnResults.remove(id) }
    fun vpnResult(): Long? = vpnResults.removeFirstOrNull()?.takeIf(::isCurrent)

    fun finish(id: Long): Boolean {
        if (!isCurrent(id)) return false
        activeId = null
        return true
    }

    fun cancel(): Long? = activeId.also { activeId = null }
}
