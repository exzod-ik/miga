package org.miga.android

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.mutableStateOf
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal data class AppCatalogState(
    val apps: List<Pair<String, String>> = emptyList(),
    val loading: Boolean,
    val error: Boolean = false,
)

class MainActivity : ComponentActivity() {
    private val model by viewModels<MigaViewModel>()
    private val appsState = mutableStateOf(AppCatalogState(loading = true))
    private val scannedServer = mutableStateOf<String?>(null)
    private val qrScanner = registerForActivityResult(ScanContract()) { result ->
        scannedServer.value = result.contents
    }
    private var catalogJob: Job? = null
    private var startJob: Job? = null
    private val permission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val id = model.startCoordinator.vpnResult() ?: return@registerForActivityResult
        if (result.resultCode == RESULT_OK) startServiceIfSafe(id)
        else if (model.startCoordinator.finish(id)) {
            model.preparedSettings = null
            VpnState.update(Phase.IDLE, "VPN permission was declined")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MigaApp(model, appsState.value, DirectSupport.available(this),
                onStart = ::prepareStart, onStop = ::stopRequested,
                onRoutesVisible = ::routesVisible,
                onScanServer = {
                    qrScanner.launch(ScanOptions().setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        .setPrompt(getString(R.string.scan_server_prompt)).setBeepEnabled(false))
                }, scannedServer = scannedServer.value,
                onScanConsumed = { scannedServer.value = null })
        }
    }

    private fun routesVisible(visible: Boolean) {
        catalogJob?.cancel()
        if (!visible) {
            appsState.value = AppCatalogState(loading = true)
            return
        }
        appsState.value = AppCatalogState(loading = true)
        catalogJob = lifecycleScope.launch {
            try {
                appsState.value = AppCatalogState(apps = withContext(Dispatchers.IO) { catalog() }, loading = false)
            } catch (ex: CancellationException) { throw ex }
            catch (_: Exception) { appsState.value = AppCatalogState(loading = false, error = true) }
        }
    }

    override fun onDestroy() {
        catalogJob?.cancel()
        val pending = if (!isChangingConfigurations || startJob?.isActive == true)
            model.startCoordinator.cancel() else null
        if (pending != null) {
            startJob?.cancel()
            model.preparedSettings = null
            PendingSession.discard(pending)
            VpnState.update(Phase.IDLE, "VPN start cancelled")
        }
        super.onDestroy()
    }

    private fun catalog(): List<Pair<String, String>> {
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return packageManager.queryIntentActivities(launcher, 0)
            .map { it.activityInfo.packageName to it.loadLabel(packageManager).toString() }
            .distinctBy { it.first }.sortedBy { it.second.lowercase() }
    }

    private fun prepareStart() {
        val id = model.startCoordinator.begin() ?: return
        VpnState.update(Phase.PREPARING, "Checking session settings")
        startJob = lifecycleScope.launch {
            try {
                val settings = model.startCoordinator.prepare(id) {
                    model.snapshot(withContext(Dispatchers.IO) { catalog().map { it.first }.toSet() })
                } ?: return@launch
                model.preparedSettings = settings
                val request = VpnService.prepare(this@MainActivity)
                if (!model.startCoordinator.isCurrent(id)) return@launch
                if (request == null) startServiceIfSafe(id) else {
                    VpnState.update(Phase.PREPARING, "Waiting for VPN permission")
                    model.startCoordinator.expectVpnResult(id)
                    permission.launch(request)
                }
            } catch (ex: CancellationException) {
                if (model.startCoordinator.isCurrent(id)) throw ex
            } catch (ex: Exception) {
                model.startCoordinator.forgetVpnResult(id)
                if (model.startCoordinator.finish(id)) {
                    model.preparedSettings = null
                    model.report(ex)
                    VpnState.update(Phase.UNAVAILABLE, "Could not prepare VPN")
                }
            }
        }
    }

    private fun startServiceIfSafe(id: Long) {
        if (!model.startCoordinator.isCurrent(id)) return
        try {
            if (VpnService.prepare(this) != null) {
                if (model.startCoordinator.finish(id)) {
                    model.preparedSettings = null
                    VpnState.update(Phase.IDLE, "VPN permission is required")
                }
                return
            }
            val settings = model.preparedSettings ?: error("Session settings are unavailable")
            if (!model.startCoordinator.isCurrent(id)) return
            VpnState.update(Phase.STARTING, "Starting local tunnel")
            PendingSession.put(id, settings)
            model.queuedRequestId = id
            ContextCompat.startForegroundService(this, Intent(this, MigaVpnService::class.java)
                .putExtra(MigaVpnService.EXTRA_REQUEST_ID, id))
            model.preparedSettings = null
            model.startCoordinator.finish(id)
        } catch (ex: Exception) {
            PendingSession.discard(id)
            if (model.queuedRequestId == id) model.queuedRequestId = null
            if (model.startCoordinator.finish(id)) {
                model.preparedSettings = null
                VpnState.update(Phase.UNAVAILABLE, "Could not start VPN")
                model.report(ex)
            }
        }
    }

    private fun stopRequested() {
        val preparingOnly = VpnState.status.value.phase == Phase.PREPARING
        val pending = model.startCoordinator.cancel()
        startJob?.cancel()
        startJob = null
        model.preparedSettings = null
        pending?.let(PendingSession::discard)
        model.queuedRequestId?.let(PendingSession::discard)
        model.queuedRequestId = null
        if (preparingOnly) VpnState.update(Phase.STOPPED, "Stopped by user")
        else startService(Intent(this, MigaVpnService::class.java).setAction(MigaVpnService.ACTION_STOP))
    }
}
