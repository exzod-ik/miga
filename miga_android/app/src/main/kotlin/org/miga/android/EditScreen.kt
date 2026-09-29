package org.miga.android

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.miga.core.Ipv4Interval

internal fun serverNeedsSsh(server: ServerProfile?, address: String): Boolean =
    server == null || runCatching { SessionValidator.endpoint(address, "1", "1").first }.getOrNull() != server.address

@Composable
internal fun EditScreen(kind: Editor, id: String?, saved: SavedSettings, locked: Boolean,
    model: MigaViewModel, onClose: () -> Unit, modifier: Modifier = Modifier) {
    val server = saved.profiles.firstOrNull { it.id == id }
    val ipRule = saved.ipv4Rules.firstOrNull { it.id == id }
    val domainRule = saved.domainRules.firstOrNull { it.id == id }
    var name by rememberSaveable(id, kind) { mutableStateOf(server?.name.orEmpty()) }
    var address by rememberSaveable(id, kind) { mutableStateOf(server?.address.orEmpty()) }
    val needsSsh = kind == Editor.SERVER && serverNeedsSsh(server, address)
    var sshUser by rememberSaveable(id, kind) { mutableStateOf("root") }
    var sshPassword by remember(id, kind) { mutableStateOf("") }
    var expression by rememberSaveable(id, kind) { mutableStateOf(ipRule?.expression ?: domainRule?.pattern.orEmpty()) }
    var profileId by rememberSaveable(id, kind) { mutableStateOf(ipRule?.profileId ?: domainRule?.profileId ?: saved.profiles.firstOrNull()?.id) }
    var saving by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    var confirmDiscard by remember { mutableStateOf(false) }
    var attempted by remember { mutableStateOf(false) }
    val errorName = stringResource(R.string.error_name)
    val errorEndpoint = stringResource(R.string.error_endpoint)
    val errorSshCredentials = stringResource(R.string.error_ssh_credentials)
    val hostQuestion by model.hostQuestion.collectAsState()
    val errorIp = stringResource(R.string.error_ip)
    val errorDomain = stringResource(R.string.error_domain)
    val errorServer = stringResource(R.string.error_server)
    val dirty = when (kind) {
        Editor.SERVER -> name != server?.name.orEmpty() || address != server?.address.orEmpty() ||
            (needsSsh && (sshPassword.isNotEmpty() || sshUser != "root"))
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
                OutlinedTextField(name, { name = it; error = "" }, Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.server_name)) }, singleLine = true,
                    isError = attempted && (name.isBlank() || name.length > 80),
                    supportingText = { if (attempted && (name.isBlank() || name.length > 80)) Text(errorName) })
                OutlinedTextField(address, { address = it; error = "" }, Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.public_ipv4)) }, singleLine = true,
                    isError = attempted && runCatching { SessionValidator.endpoint(address, "1", "1") }.isFailure,
                    supportingText = { if (attempted && runCatching { SessionValidator.endpoint(address, "1", "1") }.isFailure) Text(errorEndpoint) })
                if (needsSsh) {
                    OutlinedTextField(sshUser, { sshUser = it; error = "" }, Modifier.fillMaxWidth(),
                        label = { Text(stringResource(R.string.ssh_login)) }, singleLine = true)
                    OutlinedTextField(sshPassword, { sshPassword = it; error = "" }, Modifier.fillMaxWidth(),
                        label = { Text(stringResource(R.string.ssh_password)) },
                        visualTransformation = PasswordVisualTransformation(), singleLine = true)
                }
                if (server != null) Text("UDP ${server.firstPort}–${server.lastPort}")
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
                    runCatching { SessionValidator.endpoint(address, "1", "1") }.isFailure -> errorEndpoint
                    needsSsh && (sshUser.isBlank() || sshPassword.isBlank()) -> errorSshCredentials
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
            val success = { sshPassword = ""; saving = false; onClose() }
            val failure: (String) -> Unit = { error = it; saving = false }
            when (kind) {
                Editor.SERVER -> model.importServer(id, name, address, sshUser, sshPassword, success, failure)
                Editor.IP -> model.saveIpv4Rule(id, chosen!!, expression, success, failure)
                Editor.DOMAIN -> model.saveDomainRule(id, chosen!!, expression, success, failure)
                else -> Unit
            }
        }, enabled = !locked && !saving, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
            Text(if (needsSsh) stringResource(R.string.ssh_import) else stringResource(R.string.save))
        }
        TextButton(onClick = ::requestClose, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
            Text(stringResource(R.string.cancel))
        }
    }
    if (confirmDiscard) AlertDialog(onDismissRequest = { confirmDiscard = false },
        title = { Text(stringResource(R.string.unsaved_changes)) },
        text = { Text(stringResource(R.string.discard_question)) },
        confirmButton = { TextButton(onClick = { sshPassword = ""; confirmDiscard = false; onClose() }) { Text(stringResource(R.string.discard)) } },
        dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text(stringResource(R.string.continue_editing)) } })
    if (hostQuestion != null) AlertDialog(onDismissRequest = { model.answerHostQuestion(false) },
        title = { Text(stringResource(R.string.ssh_key_title)) },
        text = { Text(hostQuestion.orEmpty()) },
        confirmButton = { TextButton(onClick = { model.answerHostQuestion(true) }) { Text(stringResource(R.string.ssh_key_confirm)) } },
        dismissButton = { TextButton(onClick = { model.answerHostQuestion(false) }) { Text(stringResource(R.string.cancel)) } })
}
