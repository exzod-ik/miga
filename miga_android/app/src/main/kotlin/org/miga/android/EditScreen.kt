package org.miga.android

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.miga.core.Ipv4Interval

@Composable
internal fun EditScreen(kind: Editor, id: String?, saved: SavedSettings, locked: Boolean,
    model: MigaViewModel, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val server = saved.profiles.firstOrNull { it.id == id }
    val ipRule = saved.ipv4Rules.firstOrNull { it.id == id }
    val domainRule = saved.domainRules.firstOrNull { it.id == id }
    var name by rememberSaveable(id, kind) { mutableStateOf(server?.name.orEmpty()) }
    var address by rememberSaveable(id, kind) { mutableStateOf(server?.address.orEmpty()) }
    var invitation by remember(id, kind) { mutableStateOf("") }
    var expression by rememberSaveable(id, kind) { mutableStateOf(ipRule?.expression ?: domainRule?.pattern.orEmpty()) }
    var profileId by rememberSaveable(id, kind) { mutableStateOf(ipRule?.profileId ?: domainRule?.profileId ?: saved.profiles.firstOrNull()?.id) }
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var confirmDiscard by remember { mutableStateOf(false) }
    var attempted by remember { mutableStateOf(false) }
    val errorName = stringResource(R.string.error_name)
    val errorEndpoint = stringResource(R.string.error_endpoint)
    val errorIp = stringResource(R.string.error_ip)
    val errorDomain = stringResource(R.string.error_domain)
    val errorServer = stringResource(R.string.error_server)
    val errorInvitationFile = stringResource(R.string.error_invitation_file)
    val resolver = LocalContext.current.contentResolver
    val scope = rememberCoroutineScope()
    val openInvitationFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null || locked || saving) return@rememberLauncherForActivityResult
        saving = true
        error = ""
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    requireNotNull(resolver.openInputStream(uri)).use(::readInvitationFile)
                }
            }
            result.onSuccess {
                invitation = it.invitation
                if (name.isBlank()) name = it.address
            }.onFailure {
                error = errorInvitationFile
            }
            saving = false
        }
    }
    val dirty = when (kind) {
        Editor.SERVER -> name != server?.name.orEmpty() || address != server?.address.orEmpty() ||
            invitation.isNotEmpty()
        Editor.IP, Editor.DOMAIN -> expression != (ipRule?.expression ?: domainRule?.pattern.orEmpty()) ||
            profileId != (ipRule?.profileId ?: domainRule?.profileId ?: saved.profiles.firstOrNull()?.id)
        else -> false
    }
    fun requestClose() { if (saving) return; if (dirty) confirmDiscard = true else onClose() }
    BackHandler { requestClose() }
    Column(modifier.imePadding().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            BackArrow(onClick = ::requestClose)
            Text(when (kind) { Editor.SERVER -> stringResource(R.string.server_editor)
                Editor.IP -> stringResource(R.string.ip_editor)
                Editor.DOMAIN -> stringResource(R.string.domain_editor)
                else -> "" }, style = MaterialTheme.typography.headlineSmall)
        }
        if (locked) Text(stringResource(R.string.stop_to_edit))
        when (kind) {
            Editor.SERVER -> {
                if (server?.requiresInvitation == true) Text(stringResource(R.string.migration_rules_kept))
                OutlinedTextField(name, { name = it; error = "" }, Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.server_name)) }, singleLine = true,
                    isError = attempted && (name.isBlank() || name.length > 80),
                    supportingText = { if (attempted && (name.isBlank() || name.length > 80)) Text(errorName) })
                OutlinedTextField(invitation, { invitation = it; error = "" }, Modifier.fillMaxWidth(),
                    label = { Text("Приглашение miga2:") }, visualTransformation = PasswordVisualTransformation())
                OutlinedButton(onClick = { openInvitationFile.launch(arrayOf("*/*")) }, enabled = !locked && !saving) {
                    Text(stringResource(R.string.open_invitation_file))
                }
                if (server != null && !server.requiresInvitation) Text("UDP ${server.firstPort}–${server.lastPort}")
            }
            Editor.IP, Editor.DOMAIN -> {
                OutlinedTextField(expression, { expression = it; error = "" }, Modifier.fillMaxWidth(),
                    label = { Text(if (kind == Editor.IP) stringResource(R.string.ip_expression)
                        else stringResource(R.string.domain_expression)) }, singleLine = true,
                    isError = attempted && (if (kind == Editor.IP) runCatching { Ipv4Interval.parse(expression) }.isFailure else expression.isBlank()),
                    supportingText = { if (attempted && (if (kind == Editor.IP) runCatching { Ipv4Interval.parse(expression) }.isFailure else expression.isBlank()))
                        Text(if (kind == Editor.IP) errorIp else errorDomain) })
                if (kind == Editor.DOMAIN) Text(stringResource(R.string.domain_note))
                Text(stringResource(R.string.choose_server))
                saved.profiles.forEach { profile ->
                    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                        RadioButton(profileId == profile.id, onClick = { profileId = profile.id })
                        Text(profile.name, Modifier.padding(top = 12.dp))
                    }
                }
            }
            else -> Unit
        }
        if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
        Button(onClick = {
            if (saving) return@Button
            attempted = true
            error = when (kind) {
                Editor.SERVER -> when {
                    name.isBlank() || name.length > 80 -> errorName
                    (server == null || invitation.isNotBlank()) && runCatching { parseServerQr(invitation.trim()) }.isFailure -> errorEndpoint
                    else -> ""
                }
                Editor.IP -> if (runCatching { Ipv4Interval.parse(expression) }.isFailure) errorIp else ""
                Editor.DOMAIN -> if (expression.isBlank()) errorDomain else ""
                else -> ""
            }
            if (error.isNotEmpty()) return@Button
            val chosen = profileId
            if (kind != Editor.SERVER && chosen == null) { error = errorServer; return@Button }
            saving = true
            val success = { invitation = ""; saving = false; onClose() }
            val failure: (String) -> Unit = { error = it; saving = false }
            when (kind) {
                Editor.SERVER -> if (server != null && invitation.isBlank()) model.renameProfile(server.id, name, server.address, success, failure)
                    else model.importInvitation(id, name, invitation, success, failure)
                Editor.IP -> model.saveIpv4Rule(id, chosen!!, expression, success, failure)
                Editor.DOMAIN -> model.saveDomainRule(id, chosen!!, expression, success, failure)
                else -> Unit
            }
        }, enabled = !locked && !saving, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
            Text(stringResource(R.string.save))
        }
        TextButton(onClick = ::requestClose, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Text(stringResource(R.string.cancel))
        }
    }
    if (confirmDiscard) AlertDialog(onDismissRequest = { confirmDiscard = false },
        title = { Text(stringResource(R.string.unsaved_changes)) },
        text = { Text(stringResource(R.string.discard_question)) },
        confirmButton = { TextButton(onClick = { invitation = ""; confirmDiscard = false; onClose() }) { Text(stringResource(R.string.discard)) } },
        dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text(stringResource(R.string.continue_editing)) } })
}
