package org.miga.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.OsConstants
import org.miga.core.ConnectionController
import org.miga.core.ConnectionOwnerResolver
import org.miga.core.ConnectionState
import org.miga.core.LegacyMigaCodec
import org.miga.core.MultiTunnelEngine
import org.miga.core.PublicRoutes
import org.miga.core.RetryScheduler
import org.miga.core.ServerTransport
import org.miga.core.StaticIpv4RuleSet
import org.miga.core.StatsTaskScheduler
import org.miga.core.TunnelPacketLimits
import java.io.Closeable
import java.net.InetAddress
import java.util.concurrent.ThreadLocalRandom

class MigaVpnService : VpnService() {
    private val main = Handler(Looper.getMainLooper())
    private var tun: ParcelFileDescriptor? = null
    private var engine: MultiTunnelEngine? = null
    private var auxiliaryDnsTcp: AuxiliaryDnsTcpClient? = null
    private var eventDispatcher: ServerEventDispatcher? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val controllers = linkedMapOf<String, ConnectionController<Network>>()
    private var directController: ConnectionController<Network>? = null
    private var captureMode = CaptureMode.ASSIGNED_APPS
    private var replyCheck: Runnable? = null
    private var generation = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopSession(); return START_NOT_STICKY }
        val requestId = intent?.getLongExtra(EXTRA_REQUEST_ID, -1L) ?: -1L
        if (tun != null || controllers.isNotEmpty()) {
            PendingSession.discard(requestId)
            return START_NOT_STICKY
        }
        val settings = PendingSession.take(requestId)
        if (settings == null) { stopSelf(startId); return START_NOT_STICKY }
        if (settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES && !DirectSupport.available(this)) {
            VpnState.update(Phase.UNAVAILABLE, "DIRECT native library is missing for this ABI")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if ((settings.captureMode == CaptureMode.ASSIGNED_APPS && settings.assignments.isEmpty()) ||
            (settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES &&
                settings.assignments.isEmpty() && settings.ipv4Rules.isEmpty() && settings.domainRules.isEmpty())) {
            VpnState.update(Phase.UNAVAILABLE, "Valid session settings are required")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val session = ++generation
        captureMode = settings.captureMode
        VpnState.begin()
        try {
            if (settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES)
                check(DirectSupport.available(this)) { "DIRECT native library is missing for this ABI" }
            startForeground(NOTIFICATION_ID, notification())
            val builder = Builder().setSession("M.I.G.A.").setMtu(TunnelPacketLimits.TUN_MTU)
                .setBlocking(false).addAddress("10.254.83.2", 32).addDnsServer("1.1.1.1")
                .allowFamily(OsConstants.AF_INET6).setUnderlyingNetworks(emptyArray())
            for (route in PublicRoutes.publicCidrs()) builder.addRoute(route.address.toAddress(), route.prefix)
            for (name in if (settings.captureMode == CaptureMode.ASSIGNED_APPS) settings.packages else emptySet()) {
                try { builder.addAllowedApplication(name) }
                catch (_: PackageManager.NameNotFoundException) {
                    throw IllegalArgumentException("A selected application is unavailable; review the selection")
                }
            }
            // A shared UID with different profile assignments is explicitly ambiguous.
            val uidProfiles = mutableMapOf<Int, String?>()
            settings.assignments.forEach { (name, id) ->
                val uid = packageManager.getPackageUid(name, 0)
                if (uid in uidProfiles && uidProfiles[uid] != id) uidProfiles[uid] = null
                else if (uid !in uidProfiles) uidProfiles[uid] = id
            }
            if (settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES) {
                uidProfiles.keys.toList().forEach { uid ->
                    val packages = packageManager.getPackagesForUid(uid)?.toSet().orEmpty()
                    if (packages.isEmpty() || packages.any { settings.assignments[it] != uidProfiles[uid] })
                        uidProfiles[uid] = null
                }
            }
            tun = builder.establish() ?: error("VPN TUN was not established")
            val duplicate = ParcelFileDescriptor.dup(tun!!.fileDescriptor)
            val device = try { TunPacketDevice(duplicate) } catch (ex: Exception) { duplicate.close(); throw ex }
            val manager = getSystemService(ConnectivityManager::class.java)
            val adapter = AndroidConnectionOwnerResolver(manager)
            val resolver = ConnectionOwnerResolver { flow -> adapter.ownerUid(flow) }
            val delivery = ServerEventDispatcher(settings.profiles.keys, object : StatsTaskScheduler {
                override fun post(task: Runnable, delayMillis: Long) { main.postDelayed(task, delayMillis) }
                override fun remove(task: Runnable) { main.removeCallbacks(task) }
            }, { id, token, stats ->
                if (generation == session && controllers[id]?.token == token) {
                    val noResponse = VpnState.status.value.servers[id]?.noResponse == true
                    VpnState.updateServerStats(id, stats)
                    if (noResponse && VpnState.status.value.servers[id]?.noResponse == false) updateOverall()
                }
            }, { id, token ->
                if (generation == session) safeConnectionEvent { controllers[id]?.failed(token) }
            })
            eventDispatcher = delivery
            val created = MultiTunnelEngine(device, resolver, uidProfiles.toMap(), "",
                { SystemClock.elapsedRealtime() },
                delivery::offerStats,
                delivery::offerFailure,
                { main.post {
                    if (generation == session) {
                        val cleanup = release()
                        VpnState.update(Phase.UNAVAILABLE, "VPN TUN failed${cleanup?.let { "; $it" } ?: ""}")
                        stopSelf()
                    }
                } },
                rules = StaticIpv4RuleSet(if (settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES)
                    settings.ipv4Rules else emptyList()),
                allowDirect = settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES,
                domainRules = org.miga.core.DomainRuleSet(if (settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES)
                    settings.domainRules else emptyList()),
                auxiliaryDnsTcp = { query -> auxiliaryDnsTcp?.submit(query) })
            engine = created
            created.start()
            if (settings.domainRules.isNotEmpty()) auxiliaryDnsTcp = AuxiliaryDnsTcpClient(created)
            val scheduler = RetryScheduler { delay, task ->
                val runnable = Runnable { task() }
                main.postDelayed(runnable, delay)
                Closeable { main.removeCallbacks(runnable) }
            }
            settings.profiles.forEach { (id, profile) ->
                VpnState.updateServerState(id, ConnectionState.WAITING_NETWORK)
                controllers[id] = ConnectionController(scheduler,
                    { base -> ThreadLocalRandom.current().nextLong(-base / 5, base / 5 + 1) },
                    { network: Network -> network.networkHandle },
                    { network: Network, token: Long -> openTransport(id, profile, network, session, token) },
                    { state, _ -> if (generation == session) {
                        VpnState.updateServerState(id, state)
                        updateOverall()
                    } })
            }
            if (settings.captureMode == CaptureMode.PUBLIC_IPV4_RULES) {
                VpnState.updateDirectState(ConnectionState.WAITING_NETWORK)
                directController = ConnectionController(scheduler,
                    { base -> ThreadLocalRandom.current().nextLong(-base / 5, base / 5 + 1) },
                    { network: Network -> network.networkHandle },
                    { network: Network, token: Long -> openDirect(network, created, session, token) },
                    { state, _ -> if (generation == session) {
                        VpnState.updateDirectState(state)
                        updateOverall()
                    } })
            }
            val seen = mutableSetOf<Network>()
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) { if (generation == session) seen.add(network) }
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    if (generation == session && network in seen) safeConnectionEvent {
                        controllers.values.forEach { it.available(network, rank(caps)) }
                        directController?.available(network, rank(caps))
                    }
                }
                override fun onLost(network: Network) {
                    if (generation == session) {
                        seen.remove(network)
                        safeConnectionEvent {
                            controllers.values.forEach { it.lost(network) }
                            directController?.lost(network)
                        }
                    }
                }
            }
            val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
            show(Phase.WAITING, "Waiting for a physical network")
            manager.registerNetworkCallback(request, callback, main)
            networkCallback = callback
            replyCheck = object : Runnable {
                override fun run() {
                    if (generation != session) return
                    VpnState.checkNoResponse(SystemClock.elapsedRealtime())
                    engine?.let {
                        VpnState.addUnknownOwnerDrops(it.unknownOwnerDrops)
                        VpnState.updateDirectCounters(it.directCounters)
                        VpnState.updateDnsCounters(it.dnsCounters)
                    }
                    updateOverall()
                    main.postDelayed(this, 5_000)
                }
            }.also { main.postDelayed(it, 5_000) }
        } catch (ex: Exception) {
            val cleanup = release()
            VpnState.update(Phase.UNAVAILABLE, "VPN startup failed: ${ex.javaClass.simpleName}${cleanup?.let { "; $it" } ?: ""}")
            stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    private fun openTransport(id: String, profile: ServerSession, network: Network,
                              session: Long, token: Long): Closeable {
        val transport = ProtectedUdpTransport(this, network, profile.serverAddress)
        try {
            check(setUnderlyingNetworks(arrayOf(network))) { "Could not set underlying network" }
            val server = ServerTransport(id, token, transport,
                LegacyMigaCodec(profile.xorKey, profile.swapKey), profile.serverIp,
                profile.firstPort, profile.lastPort,
                { ThreadLocalRandom.current().nextInt(profile.firstPort, profile.lastPort + 1) })
            check(generation == session)
            eventDispatcher?.advance(id, token)
            checkNotNull(engine).attach(server)
            return Closeable { engine?.detach(id, token) }
        } catch (ex: Exception) {
            transport.close()
            throw ex
        }
    }

    private fun openDirect(network: Network, created: MultiTunnelEngine,
                           session: Long, token: Long): Closeable {
        check(setUnderlyingNetworks(arrayOf(network))) { "Could not set DIRECT underlying network" }
        val stack = HevDirectPacketStack(this, network,
            { bytes -> created.offerDirectResponse(token, bytes) },
            { main.post {
                if (generation == session && directController?.token == token)
                    safeConnectionEvent { directController?.failed(token) }
            } })
        try {
            check(generation == session)
            created.attachDirect(stack, token)
            return Closeable { created.detachDirect(token) }
        } catch (ex: Exception) { stack.close(); throw ex }
    }

    private fun updateOverall() {
        val servers = VpnState.status.value.servers.values
        val states = servers.map { it.state }
        val noReply = servers.count { it.noResponse }
        val directState = VpnState.status.value.directState
        val directReady = captureMode != CaptureMode.PUBLIC_IPV4_RULES || directState == ConnectionState.RUNNING
        val phase = when {
            !directReady && states.any { it == ConnectionState.RUNNING } -> Phase.PARTIAL
            !directReady && directState == ConnectionState.RETRYING -> Phase.RETRYING
            !directReady -> Phase.WAITING
            states.isEmpty() -> Phase.RUNNING
            states.all { it == ConnectionState.WAITING_NETWORK } -> Phase.WAITING
            states.all { it == ConnectionState.RUNNING } && noReply == states.size -> Phase.NO_RESPONSE
            states.all { it == ConnectionState.RUNNING } && noReply > 0 -> Phase.PARTIAL
            states.all { it == ConnectionState.RUNNING } -> Phase.RUNNING
            states.any { it == ConnectionState.RUNNING } -> Phase.PARTIAL
            states.any { it == ConnectionState.RETRYING } -> Phase.RETRYING
            else -> Phase.STARTING
        }
        val running = states.count { it == ConnectionState.RUNNING }
        val message = "$running/${states.size} local transports running; $noReply without valid replies" +
            if (captureMode == CaptureMode.PUBLIC_IPV4_RULES) "; DIRECT ${directState ?: "waiting"}" else ""
        if (VpnState.status.value.phase != phase || VpnState.status.value.message != message) show(phase, message)
    }

    private fun safeConnectionEvent(action: () -> Unit) {
        try { action() } catch (ex: Exception) {
            val cleanup = release()
            VpnState.update(Phase.UNAVAILABLE, "Connection cleanup failed: ${ex.javaClass.simpleName}${cleanup?.let { "; $it" } ?: ""}")
            stopSelf()
        }
    }

    private fun rank(caps: NetworkCapabilities?): Int? {
        if (caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 0
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 2
            else -> null
        }
    }

    private fun show(phase: Phase, message: String) {
        VpnState.update(phase, message)
        startForeground(NOTIFICATION_ID, notification())
    }

    override fun onRevoke() {
        val cleanup = release()
        VpnState.update(Phase.REVOKED, "VPN permission revoked${cleanup?.let { "; $it" } ?: ""}")
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        val cleanup = release()
        if (cleanup != null) VpnState.update(Phase.UNAVAILABLE, cleanup)
        super.onDestroy()
    }

    private fun stopSession() {
        VpnState.update(Phase.STOPPING, "Stopping")
        val cleanup = release()
        if (cleanup == null) VpnState.update(Phase.STOPPED, "Stopped by user")
        else VpnState.update(Phase.UNAVAILABLE, cleanup)
        stopSelf()
    }

    private fun release(): String? {
        generation++
        val problems = mutableListOf<String>()
        val callback = networkCallback
        networkCallback = null
        if (callback != null) runCatching { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(callback) }
            .onFailure { problems.add("network callback ${it.javaClass.simpleName}") }
        replyCheck?.let { main.removeCallbacks(it) }; replyCheck = null
        runCatching { auxiliaryDnsTcp?.close() }.onFailure { problems.add("DNS TCP ${it.javaClass.simpleName}") }
        auxiliaryDnsTcp = null
        runCatching { eventDispatcher?.close() }.onFailure { problems.add("statistics ${it.javaClass.simpleName}") }
        eventDispatcher = null
        val oldControllers = controllers.values.toList()
        controllers.clear()
        val oldDirect = directController
        directController = null
        runCatching { oldDirect?.close() }.onFailure { problems.add("DIRECT ${it.javaClass.simpleName}") }
        oldControllers.forEach { runCatching { it.close() }.onFailure { ex -> problems.add("transport ${ex.javaClass.simpleName}") } }
        runCatching { engine?.close() }.onFailure { problems.add("engine ${it.javaClass.simpleName}") }
        engine = null
        captureMode = CaptureMode.ASSIGNED_APPS
        VpnState.updateDirectState(null)
        val original = tun
        tun = null
        runCatching { original?.close() }.onFailure { problems.add("TUN ${it.javaClass.simpleName}") }
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
            .onFailure { problems.add("foreground ${it.javaClass.simpleName}") }
        return if (problems.isEmpty()) null else "Cleanup failed: ${problems.joinToString()}"
    }

    private fun notification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "M.I.G.A. VPN", NotificationManager.IMPORTANCE_LOW))
        val stop = Intent(this, MigaVpnService::class.java).setAction(ACTION_STOP)
        val pending = PendingIntent.getService(this, 1, stop, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val open = PendingIntent.getActivity(this, 2, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val status = VpnState.status.value
        val active = status.phase in setOf(Phase.RUNNING, Phase.PARTIAL, Phase.NO_RESPONSE, Phase.REPLIED,
            Phase.NETWORK_LOST, Phase.WAITING, Phase.RETRYING)
        val running = status.servers.values.count { it.state == org.miga.core.ConnectionState.RUNNING }
        val summary = if (status.phase == Phase.PARTIAL || status.phase == Phase.NO_RESPONSE)
            getString(R.string.notification_problem, running, status.servers.size)
            else if (active) getString(R.string.notification_servers, running, status.servers.size)
            else if (status.phase == Phase.UNAVAILABLE) getString(R.string.state_unavailable)
            else getString(R.string.state_connecting)
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(if (active) R.string.notification_title else R.string.notification_starting))
            .setContentText(summary)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(Icon.createWithResource(this, android.R.drawable.ic_media_pause), getString(R.string.notification_stop), pending).build())
            .build()
    }

    private fun Int.toAddress(): InetAddress = InetAddress.getByAddress(byteArrayOf(
        (this ushr 24).toByte(), (this ushr 16).toByte(), (this ushr 8).toByte(), toByte()))

    companion object {
        const val ACTION_STOP = "org.miga.android.STOP"
        const val EXTRA_REQUEST_ID = "org.miga.android.REQUEST_ID"
        private const val CHANNEL = "miga_vpn"
        private const val NOTIFICATION_ID = 1001
    }
}
