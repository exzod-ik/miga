package org.miga.android

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.CompletableDeferred

class MigaViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = SettingsRepository(DataStoreSettings(application), KeystoreSecretStore(application)) {
        VpnState.status.value.phase in setOf(Phase.PREPARING, Phase.STARTING, Phase.RUNNING, Phase.PARTIAL,
            Phase.NO_RESPONSE, Phase.REPLIED, Phase.NETWORK_LOST, Phase.WAITING, Phase.RETRYING, Phase.STOPPING)
    }
    private val mutableSettings = MutableStateFlow<SavedSettings?>(null)
    val settings = mutableSettings.asStateFlow()
    private val mutableMessage = MutableStateFlow("Loading settings")
    val message = mutableMessage.asStateFlow()
    val status = VpnState.status
    private val sshConfig = ServerConfigSsh(application)
    private var hostDecision: CompletableDeferred<Boolean>? = null
    private val mutableHostQuestion = MutableStateFlow<String?>(null)
    val hostQuestion = mutableHostQuestion.asStateFlow()
    internal val startCoordinator = StartCoordinator()
    internal var queuedRequestId: Long? = null
    internal var preparedSettings: SessionSettings? = null

    init { viewModelScope.launch {
        try { mutableSettings.value = repository.load(); mutableMessage.value = "" }
        catch (ex: CancellationException) { throw ex }
        catch (ex: Exception) { mutableMessage.value = safeMessage(ex) }
    } }

    private fun safeMessage(ex: Exception): String = when (ex) {
        is com.jcraft.jsch.JSchException -> "SSH connection failed: ${ex.message ?: "unknown error"}"
        is org.json.JSONException -> "Server configuration is invalid"
        is SettingsCorrupt, is SecretUnavailable, is IllegalArgumentException, is IllegalStateException ->
            ex.message ?: "Operation failed"
        else -> "Settings could not be saved or loaded (${ex.javaClass.simpleName})"
    }

    fun saveProfile(id: String?, name: String, address: String, first: String, last: String,
                    xorBase64: String, swapBase64: String, replaceKeys: Boolean, onSuccess: () -> Unit,
                    onFailure: (String) -> Unit = {}) {
        change(onSuccess, onFailure) {
            val keys = if (replaceKeys || id == null) SecretKeys(
                SessionValidator.keyBase64(xorBase64, 128), SessionValidator.keyBase64(swapBase64, 8)) else null
            repository.saveProfile(id, name, address, first, last, keys)
        }
    }

    fun importServer(id: String?, name: String, address: String, username: String, password: String,
                     onSuccess: () -> Unit, onFailure: (String) -> Unit) {
        change(onSuccess, onFailure) {
            require(name.isNotBlank() && name.length <= 80) { "Enter a server name" }
            // Validate the public address before any SSH connection is attempted.
            val normalizedAddress = SessionValidator.endpoint(address, "1", "1").first
            val existing = id?.let { profileId ->
                repository.load().profiles.firstOrNull { it.id == profileId }
                    ?: throw IllegalArgumentException("Profile no longer exists")
            }
            if (existing != null && normalizedAddress == existing.address)
                return@change repository.renameProfile(existing.id, name, normalizedAddress)
            val remote = sshConfig.fetch(address.trim(), username, password) { question ->
                val decision = CompletableDeferred<Boolean>()
                hostDecision = decision
                mutableHostQuestion.value = question
                try { decision.await() }
                finally { hostDecision = null; mutableHostQuestion.value = null }
            }
            repository.saveProfile(id, name, address, remote.firstPort.toString(),
                remote.lastPort.toString(), remote.keys)
        }
    }

    fun answerHostQuestion(accept: Boolean) { hostDecision?.complete(accept) }

    fun deleteProfile(id: String) = change { repository.deleteProfile(id) }
    fun selectProfile(id: String) = change { repository.selectProfile(id) }
    fun togglePackage(name: String) = change { repository.togglePackage(name) }
    fun assignPackage(name: String, profileId: String?) = change { repository.assignPackage(name, profileId) }
    fun selectDnsProfile(id: String) = change { repository.selectDnsProfile(id) }
    fun saveDomainRule(id: String?, profileId: String, pattern: String, onSuccess: () -> Unit = {},
                       onFailure: (String) -> Unit = {}) =
        change(onSuccess, onFailure) { repository.saveDomainRule(id, profileId, pattern) }
    fun deleteDomainRule(id: String) = change { repository.deleteDomainRule(id) }
    fun saveIpv4Rule(id: String?, profileId: String, expression: String, onSuccess: () -> Unit,
                     onFailure: (String) -> Unit = {}) = change(onSuccess, onFailure) {
        repository.saveIpv4Rule(id, profileId, expression)
    }
    fun deleteIpv4Rule(id: String) = change { repository.deleteIpv4Rule(id) }

    private fun change(onSuccess: () -> Unit = {}, onFailure: (String) -> Unit = {},
                       action: suspend () -> SavedSettings) {
        if (mutableSettings.value == null) return
        viewModelScope.launch {
            try {
                val updated = action()
                currentCoroutineContext().ensureActive()
                mutableSettings.value = updated
                mutableMessage.value = "Saved"
                onSuccess()
            } catch (ex: CancellationException) { throw ex }
            catch (ex: Exception) { val reason = safeMessage(ex); mutableMessage.value = reason; onFailure(reason) }
        }
    }

    suspend fun snapshot(availablePackages: Set<String>): SessionSettings =
        repository.snapshot(availablePackages, DirectSupport.available(getApplication()))
    fun report(ex: Exception) { mutableMessage.value = safeMessage(ex) }
}
