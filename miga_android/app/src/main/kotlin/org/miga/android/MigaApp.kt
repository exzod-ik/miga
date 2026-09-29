package org.miga.android

import android.widget.ImageView
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.miga.core.ConnectionState

private val mint = Color(0xFF0CF8B7)
private val activeText = Color(0xFF0E1347)
private const val githubUrl = "https://github.com/exzod-ik/miga"
private val activePhases = setOf(Phase.RUNNING, Phase.PARTIAL, Phase.NO_RESPONSE, Phase.REPLIED,
    Phase.NETWORK_LOST, Phase.WAITING, Phase.RETRYING)
internal fun editsLocked(phase: Phase) = phase in activePhases || phase in
    setOf(Phase.PREPARING, Phase.STARTING, Phase.STOPPING)
internal fun tunnelOn(phase: Phase) = phase in activePhases

private enum class Page { TUNNEL, SERVERS, ROUTES, SETTINGS, DIAGNOSTICS }
private enum class RouteTab { APPS, IP, DOMAINS }
internal enum class Editor { NONE, SERVER, IP, DOMAIN }

@Composable
internal fun MigaApp(model: MigaViewModel, catalog: AppCatalogState, directAvailable: Boolean,
            onStart: () -> Unit, onStop: () -> Unit, onRoutesVisible: (Boolean) -> Unit,
            onScanServer: () -> Unit, scannedServer: String?, onScanConsumed: () -> Unit) {
    val context = LocalContext.current
    val uriHandler = LocalUriHandler.current
    val saved by model.settings.collectAsStateWithLifecycle()
    val status by model.status.collectAsStateWithLifecycle()
    val message by model.message.collectAsStateWithLifecycle()
    val themePreference = remember { ThemePreference(context.applicationContext) }
    val theme by themePreference.choice.collectAsState(initial = ThemeChoice.SYSTEM)
    val scope = rememberCoroutineScope()
    val dark = when (theme) {
        ThemeChoice.SYSTEM -> androidx.compose.foundation.isSystemInDarkTheme()
        ThemeChoice.DARK -> true
        ThemeChoice.LIGHT -> false
    }
    val colors = if (dark) darkColors else lightColors
    var pageName by rememberSaveable { mutableStateOf(Page.TUNNEL.name) }
    var settingsReturnPage by rememberSaveable { mutableStateOf(Page.SERVERS.name) }
    var editorName by rememberSaveable { mutableStateOf(Editor.NONE.name) }
    var editingId by rememberSaveable { mutableStateOf<String?>(null) }
    var routeTabName by rememberSaveable { mutableStateOf(RouteTab.APPS.name) }
    var search by rememberSaveable { mutableStateOf("") }
    var assignedOnly by rememberSaveable { mutableStateOf(false) }
    val snack = remember { SnackbarHostState() }
    val needServer = stringResource(R.string.need_server)
    val needRoutes = stringResource(R.string.need_routes)
    val needPublicRules = stringResource(R.string.need_public_rules)
    val startFailed = stringResource(R.string.state_unavailable)
    val githubOpenFailed = stringResource(R.string.github_open_failed)
    val page = Page.valueOf(pageName)
    val editor = Editor.valueOf(editorName)
    val locked = editsLocked(status.phase)
    LaunchedEffect(page, directAvailable) {
        if (page == Page.ROUTES && !directAvailable) routeTabName = RouteTab.APPS.name
    }
    LaunchedEffect(page) { onRoutesVisible(page == Page.ROUTES) }
    BackHandler(enabled = editor == Editor.NONE && page in listOf(Page.SETTINGS, Page.DIAGNOSTICS)) {
        pageName = if (page == Page.DIAGNOSTICS) Page.SERVERS.name else settingsReturnPage
    }
    LaunchedEffect(message) { if (message.isNotBlank() && message != "Loading settings") snack.showSnackbar(message) }
    LaunchedEffect(status.phase, status.message) {
        if (status.phase == Phase.UNAVAILABLE) snack.showSnackbar(startFailed)
    }
    MaterialTheme(colorScheme = colors) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = colors.background,
            snackbarHost = { SnackbarHost(snack) },
            bottomBar = {
                if (editor == Editor.NONE && page in listOf(Page.TUNNEL, Page.SERVERS, Page.ROUTES))
                    NavigationBar(containerColor = colors.surface) {
                        listOf(Page.TUNNEL, Page.SERVERS, Page.ROUTES).forEach { item ->
                            NavigationBarItem(selected = page == item, onClick = { pageName = item.name },
                                icon = {
                                    Icon(painterResource(when (item) {
                                        Page.TUNNEL -> R.drawable.ic_nav_tunnel
                                        Page.SERVERS -> R.drawable.ic_nav_servers
                                        else -> R.drawable.ic_nav_routes
                                    }), contentDescription = null, modifier = Modifier.size(20.dp))
                                },
                                label = { Text(pageTitle(item)) }, alwaysShowLabel = true,
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = colors.onSurface, selectedTextColor = colors.onSurface,
                                    unselectedIconColor = colors.onSurfaceVariant, unselectedTextColor = colors.onSurfaceVariant,
                                    indicatorColor = colors.surfaceVariant))
                        }
                    }
            }
        ) { padding ->
            val base = Modifier.fillMaxSize().padding(padding)
            if (editor != Editor.NONE && saved != null) {
                EditScreen(editor, editingId, saved!!, locked, model,
                    onClose = { editorName = Editor.NONE.name }, modifier = base)
            } else when (page) {
                Page.TUNNEL -> Column(base.padding(20.dp)) {
                    Header(stringResource(R.string.app_name), onSettings = {
                        settingsReturnPage = Page.TUNNEL.name; pageName = Page.SETTINGS.name
                    })
                    TunnelScreen(status.phase, saved,
                        onStart = {
                            val settings = saved
                            when {
                                settings == null || settings.profiles.isEmpty() -> { pageName = Page.SERVERS.name; scope.launch { snack.showSnackbar(needServer) } }
                                settings.assignments.isEmpty() && (!directAvailable ||
                                    settings.ipv4Rules.isEmpty() && settings.domainRules.isEmpty()) -> {
                                    pageName = Page.ROUTES.name
                                    scope.launch { snack.showSnackbar(if (directAvailable)
                                        needPublicRules else needRoutes) }
                                }
                                else -> onStart()
                            }
                        }, onStop = onStop, modifier = Modifier.fillMaxWidth().weight(1f))
                }
                Page.SERVERS -> PageColumn(base) {
                    Header(pageTitle(page), onSettings = { settingsReturnPage = Page.SERVERS.name; pageName = Page.SETTINGS.name })
                    if (saved == null) Text(stringResource(R.string.settings_unavailable))
                    else ServersScreen(saved!!, status, locked,
                        onEdit = { id -> editingId = id; editorName = Editor.SERVER.name }, model = model,
                        onDiagnostics = { pageName = Page.DIAGNOSTICS.name },
                        onRoutes = { pageName = Page.ROUTES.name }, onScan = onScanServer,
                        scannedServer = scannedServer, onScanConsumed = onScanConsumed)
                }
                Page.ROUTES -> Column(base.padding(20.dp)) {
                    Header(pageTitle(page), onSettings = { settingsReturnPage = Page.ROUTES.name; pageName = Page.SETTINGS.name })
                    if (saved == null) Text(stringResource(R.string.settings_unavailable))
                    else RoutesScreen(saved!!, catalog, locked, directAvailable, model, search, { search = it },
                        assignedOnly, { assignedOnly = it },
                        if (directAvailable) RouteTab.valueOf(routeTabName) else RouteTab.APPS,
                        { routeTabName = it.name }, onEdit = { kind, id -> editingId = id; editorName = kind.name },
                        onReloadApps = { onRoutesVisible(true) }, modifier = Modifier.weight(1f))
                }
                Page.SETTINGS -> PageColumn(base) {
                    Header(pageTitle(page), onBack = { pageName = settingsReturnPage })
                    Text(stringResource(R.string.theme), style = MaterialTheme.typography.titleMedium)
                    ThemeChoice.entries.forEach { choice ->
                        Row(Modifier.fillMaxWidth().clickable { scope.launch { themePreference.save(choice) } }
                            .heightIn(min = 48.dp), verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(theme == choice, onClick = { scope.launch { themePreference.save(choice) } })
                            Text(when (choice) {
                                ThemeChoice.SYSTEM -> stringResource(R.string.theme_system)
                                ThemeChoice.LIGHT -> stringResource(R.string.theme_light)
                                ThemeChoice.DARK -> stringResource(R.string.theme_dark)
                            })
                        }
                    }
                    Column {
                        val row = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                        Row(row, verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.version,
                                context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: ""))
                        }
                        Row(row.clickable {
                            runCatching { uriHandler.openUri(githubUrl) }
                                .onFailure { scope.launch { snack.showSnackbar(githubOpenFailed) } }
                        }, verticalAlignment = Alignment.CenterVertically) {
                            val label = stringResource(R.string.github_label)
                            Text(buildAnnotatedString {
                                append(label)
                                append(" ")
                                pushStyle(SpanStyle(textDecoration = TextDecoration.Underline))
                                append(githubUrl)
                                pop()
                            })
                        }
                        Row(row, verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.author_info))
                        }
                        Row(row, verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.license_info))
                        }
                    }
                }
                Page.DIAGNOSTICS -> PageColumn(base) {
                    Header(pageTitle(page), onBack = { pageName = Page.SERVERS.name })
                    DiagnosticsScreen(status, saved)
                }
            }
        }
    }
}

private val lightColors = lightColorScheme(background = Color.White, surface = Color.White,
    surfaceVariant = Color(0xFFF3F3F3), onBackground = Color(0xFF111111), onSurface = Color(0xFF111111),
    onSurfaceVariant = Color(0xFF626262), primary = Color(0xFF171717), onPrimary = Color.White,
    secondary = Color(0xFF171717), onSecondary = Color.White, secondaryContainer = Color(0xFFF3F3F3),
    onSecondaryContainer = Color(0xFF111111), primaryContainer = Color(0xFFF3F3F3),
    onPrimaryContainer = Color(0xFF111111), surfaceTint = Color.Transparent, outline = Color(0xFFE5E5E5))
private val darkColors = darkColorScheme(background = Color.Black, surface = Color(0xFF0C0C0C),
    surfaceVariant = Color(0xFF191919), onBackground = Color(0xFFF5F5F5), onSurface = Color(0xFFF5F5F5),
    onSurfaceVariant = Color(0xFFABABAB), primary = Color(0xFFF0F0F0), onPrimary = Color.Black,
    secondary = Color(0xFFF0F0F0), onSecondary = Color.Black, secondaryContainer = Color(0xFF191919),
    onSecondaryContainer = Color(0xFFF5F5F5), primaryContainer = Color(0xFF191919),
    onPrimaryContainer = Color(0xFFF5F5F5), surfaceTint = Color.Transparent, outline = Color(0xFF292929))

@Composable private fun pageTitle(page: Page) = when (page) {
    Page.TUNNEL -> stringResource(R.string.tunnel)
    Page.SERVERS -> stringResource(R.string.servers)
    Page.ROUTES -> stringResource(R.string.routes)
    Page.SETTINGS -> stringResource(R.string.settings)
    Page.DIAGNOSTICS -> stringResource(R.string.diagnostics)
}

@Composable private fun PageColumn(modifier: Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.imePadding().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp), content = content)
}

@Composable private fun Header(title: String, onBack: (() -> Unit)? = null, onSettings: (() -> Unit)? = null) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        if (onBack != null) BackArrow(onClick = onBack)
        Text(title, Modifier.weight(1f), style = MaterialTheme.typography.headlineSmall)
        if (onSettings != null) IconButton(onClick = onSettings, modifier = Modifier.size(48.dp)) {
            Icon(painterResource(R.drawable.ic_more_vert), contentDescription = stringResource(R.string.settings))
        }
    }
}

@Composable internal fun BackArrow(onClick: () -> Unit) {
    IconButton(onClick = onClick, modifier = Modifier.size(48.dp)) {
        Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.back))
    }
}

@Composable private fun TunnelScreen(phase: Phase, saved: SavedSettings?,
    onStart: () -> Unit, onStop: () -> Unit, modifier: Modifier = Modifier) {
    val on = tunnelOn(phase)
    val waiting = phase == Phase.PREPARING || phase == Phase.STARTING
    val stopping = phase == Phase.STOPPING
    val label = when {
        stopping -> stringResource(R.string.stopping)
        waiting -> stringResource(R.string.cancel_start)
        on -> stringResource(R.string.turn_off)
        else -> stringResource(R.string.turn_on)
    }
    BoxWithConstraints(modifier, contentAlignment = Alignment.Center) {
        val diameter = minOf(260.dp, maxWidth - 40.dp, maxHeight - 32.dp).coerceAtLeast(120.dp)
        Surface(onClick = { if (waiting || on) onStop() else onStart() }, enabled = !stopping,
            modifier = Modifier.size(diameter).semantics { contentDescription = label },
            shape = CircleShape, border = BorderStroke(3.dp, mint),
            color = if (on) mint else MaterialTheme.colorScheme.background,
            contentColor = if (on) activeText else MaterialTheme.colorScheme.onBackground) {
            Box(contentAlignment = Alignment.Center) {
                Text(label, style = MaterialTheme.typography.headlineMedium)
            }
        }
    }
}

@Composable private fun ServersScreen(saved: SavedSettings, status: VpnStatus, locked: Boolean,
    onEdit: (String?) -> Unit, model: MigaViewModel, onDiagnostics: () -> Unit, onRoutes: () -> Unit,
    onScan: () -> Unit, scannedServer: String?, onScanConsumed: () -> Unit) {
    var qrError by remember { mutableStateOf("") }
    var pendingQr by remember { mutableStateOf<ServerQr?>(null) }
    LaunchedEffect(scannedServer) {
        if (scannedServer != null) {
            qrError = ""
            pendingQr = try { parseServerQr(scannedServer) }
                catch (_: Exception) { qrError = "Неверный QR-код сервера M.I.G.A."; null }
            onScanConsumed()
        }
    }
    if (locked) Text(stringResource(R.string.stop_to_edit), color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (saved.profiles.isEmpty()) Text(stringResource(R.string.no_servers))
    saved.profiles.forEach { profile ->
        val assignmentCount = saved.assignments.values.count { it == profile.id }
        val ruleCount = saved.ipv4Rules.count { it.profileId == profile.id } + saved.domainRules.count { it.profileId == profile.id }
        var deleteConfirm by remember { mutableStateOf(false) }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(profile.name, style = MaterialTheme.typography.titleLarge)
                Text(profile.address, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.server_usage, assignmentCount, ruleCount))
                Text(status.servers[profile.id]?.let { server ->
                    when { server.noResponse -> stringResource(R.string.no_server_reply)
                        else -> connectionLabel(server.state) }
                } ?: if (assignmentCount + ruleCount == 0) stringResource(R.string.not_used)
                    else if (locked) stringResource(R.string.state_connecting)
                    else stringResource(R.string.tunnel_state_off))
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = { onEdit(profile.id) }, enabled = !locked) { Text(stringResource(R.string.edit)) }
                    TextButton(onClick = { deleteConfirm = true }, enabled = !locked) { Text(stringResource(R.string.delete)) }
                    TextButton(onClick = onDiagnostics) { Text(stringResource(R.string.diagnostics)) }
                }
            }
        }
        if (deleteConfirm) AlertDialog(onDismissRequest = { deleteConfirm = false },
            title = { Text(stringResource(R.string.delete_server, profile.name)) },
            text = { Text(if (assignmentCount + ruleCount > 0) stringResource(R.string.server_dependencies, assignmentCount, ruleCount)
                else stringResource(R.string.delete_confirm)) },
            confirmButton = { TextButton(onClick = {
                deleteConfirm = false
                if (assignmentCount + ruleCount == 0) model.deleteProfile(profile.id) else onRoutes()
            }) { Text(if (assignmentCount + ruleCount == 0) stringResource(R.string.delete) else stringResource(R.string.routes)) } },
            dismissButton = { TextButton(onClick = { deleteConfirm = false }) { Text(stringResource(R.string.cancel)) } })
    }
    if (qrError.isNotEmpty()) Text(qrError, color = MaterialTheme.colorScheme.error)
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { onEdit(null) }, enabled = !locked,
            modifier = Modifier.weight(1f).heightIn(min = 56.dp)) { Text(stringResource(R.string.add_server_manual)) }
        Button(onClick = onScan, enabled = !locked,
            modifier = Modifier.weight(1f).heightIn(min = 56.dp)) { Text(stringResource(R.string.add_server_qr)) }
    }
    pendingQr?.let { qr ->
        AlertDialog(onDismissRequest = { pendingQr = null },
            title = { Text(stringResource(R.string.import_server_qr)) },
            text = { Text("${qr.address} · UDP ${qr.firstPort}–${qr.lastPort}\n${stringResource(R.string.qr_secret_warning)}") },
            confirmButton = { TextButton(onClick = {
                if (locked) { pendingQr = null; return@TextButton }
                if (saved.profiles.any { it.address == qr.address }) {
                    qrError = "Сервер с этим адресом уже добавлен"
                    pendingQr = null
                    return@TextButton
                }
                model.saveProfile(null, qr.address, qr.address, qr.firstPort.toString(),
                    qr.lastPort.toString(), qr.xor, qr.swap, true,
                    onSuccess = { pendingQr = null }, onFailure = { qrError = it; pendingQr = null })
            }) { Text(stringResource(R.string.add_server)) } },
            dismissButton = { TextButton(onClick = { pendingQr = null }) { Text(stringResource(R.string.cancel)) } })
    }
}

@Composable private fun RoutesScreen(saved: SavedSettings, catalog: AppCatalogState, locked: Boolean,
    directAvailable: Boolean, model: MigaViewModel, search: String, onSearch: (String) -> Unit,
    assignedOnly: Boolean, onAssignedOnly: (Boolean) -> Unit, tab: RouteTab, onTab: (RouteTab) -> Unit,
    onEdit: (Editor, String?) -> Unit, onReloadApps: () -> Unit, modifier: Modifier = Modifier) {
    val packageManager = LocalContext.current.packageManager
    val sharedUidConflict by produceState(emptySet<String>(), saved.assignments) {
        value = withContext(Dispatchers.IO) {
            saved.assignments.keys.mapNotNull { name ->
                runCatching { packageManager.getPackageUid(name, 0) }.getOrNull()?.let { name to it }
            }.groupBy { it.second }.values.filter { group ->
                group.mapNotNull { saved.assignments[it.first] }.distinct().size > 1
            }.flatMap { group -> group.map { it.first } }.toSet()
        }
    }
    Column(modifier, verticalArrangement = Arrangement.spacedBy(12.dp)) {
    if (locked) Text(stringResource(R.string.stop_to_edit), color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (!directAvailable) Text(stringResource(R.string.direct_unavailable), color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (directAvailable)
        Text(stringResource(R.string.route_priority), color = MaterialTheme.colorScheme.onSurfaceVariant)
    PrimaryTabRow(selectedTabIndex = tab.ordinal) {
        RouteTab.entries.forEach { item -> Tab(selected = item == tab, onClick = { onTab(item) },
            enabled = directAvailable || item == RouteTab.APPS,
            text = { Text(when (item) { RouteTab.APPS -> stringResource(R.string.applications)
                RouteTab.IP -> stringResource(R.string.ip_rules); RouteTab.DOMAINS -> stringResource(R.string.domains) },
                color = if (!directAvailable && item != RouteTab.APPS)
                    MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f) else Color.Unspecified) }) }
    }
    when (tab) {
        RouteTab.APPS -> {
            OutlinedTextField(search, onSearch, modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.search_apps)) }, singleLine = true)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(!assignedOnly, { onAssignedOnly(false) }, label = { Text(stringResource(R.string.available)) })
                FilterChip(assignedOnly, { onAssignedOnly(true) }, label = { Text(stringResource(R.string.assigned)) })
            }
            when {
                catalog.loading -> {
                    CircularProgressIndicator()
                    Text(stringResource(R.string.loading_apps))
                }
                catalog.error -> {
                    Text(stringResource(R.string.apps_load_failed), color = MaterialTheme.colorScheme.error)
                    TextButton(onClick = onReloadApps) { Text(stringResource(R.string.retry)) }
                }
                else -> {
                    val visible = catalog.apps.map { it.first }.toSet()
                    val unavailable = (saved.selectedPackages - visible)
                        .filter { !assignedOnly || it in saved.assignments }
                    val filtered = catalog.apps.filter { (name, label) ->
                        (!assignedOnly || name in saved.assignments) &&
                            (search.isBlank() || name.contains(search, true) || label.contains(search, true))
                    }
                    LazyColumn(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        items(unavailable, key = { "missing:$it" }) { name ->
                            Text(stringResource(R.string.unavailable_app, name))
                            TextButton(enabled = !locked, onClick = { model.assignPackage(name, null) }) {
                                Text(stringResource(R.string.remove_assignment))
                            }
                        }
                        items(filtered, key = { it.first }) { (name, label) ->
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                                    AndroidView(factory = { context -> ImageView(context).apply {
                                        scaleType = ImageView.ScaleType.FIT_CENTER
                                    } }, update = { view -> view.setImageDrawable(
                                        runCatching { packageManager.getApplicationIcon(name) }.getOrNull()) },
                                        modifier = Modifier.size(40.dp))
                                    Column {
                                        Text(label, style = MaterialTheme.typography.titleMedium)
                                        Text(name, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    }
                                }
                                if (name in sharedUidConflict) Text(stringResource(R.string.shared_uid_conflict),
                                    color = MaterialTheme.colorScheme.error)
                                ProfileSelector(saved, saved.assignments[name], locked, includeNone = true) {
                                    model.assignPackage(name, it)
                                }
                            }
                        }
                    }
                }
            }
        }
        RouteTab.IP -> {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            saved.ipv4Rules.forEach { rule -> RuleRow(rule.expression, saved.profiles.firstOrNull { it.id == rule.profileId }?.name.orEmpty(),
                locked, { onEdit(Editor.IP, rule.id) }, { model.deleteIpv4Rule(rule.id) }) }
            Button(onClick = { onEdit(Editor.IP, null) }, enabled = !locked) { Text(stringResource(R.string.add_rule)) }
            }
        }
        RouteTab.DOMAINS -> {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.domain_note), color = MaterialTheme.colorScheme.onSurfaceVariant)
            saved.domainRules.forEach { rule -> RuleRow(rule.pattern, saved.profiles.firstOrNull { it.id == rule.profileId }?.name.orEmpty(),
                locked, { onEdit(Editor.DOMAIN, rule.id) }, { model.deleteDomainRule(rule.id) }) }
            Button(onClick = { onEdit(Editor.DOMAIN, null) }, enabled = !locked) { Text(stringResource(R.string.add_rule)) }
            }
        }
    }
    }
}

@Composable private fun RuleRow(expression: String, profile: String, locked: Boolean, onEdit: () -> Unit, onDelete: () -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.fillMaxWidth().padding(12.dp)) {
            Text("$expression → $profile")
            Row {
                TextButton(onClick = onEdit, enabled = !locked) { Text(stringResource(R.string.edit)) }
                TextButton(onClick = onDelete, enabled = !locked) { Text(stringResource(R.string.delete)) }
            }
        }
    }
}

@Composable private fun ProfileSelector(saved: SavedSettings, selected: String?, locked: Boolean,
    includeNone: Boolean = false, onSelect: (String?) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        OutlinedButton(onClick = { expanded = true }, enabled = !locked, modifier = Modifier.heightIn(min = 48.dp)) {
            Text(saved.profiles.firstOrNull { it.id == selected }?.name ?: stringResource(R.string.unassigned))
        }
        DropdownMenu(expanded, onDismissRequest = { expanded = false }) {
            if (includeNone) DropdownMenuItem(text = { Text(stringResource(R.string.unassigned)) }, onClick = { expanded = false; onSelect(null) })
            saved.profiles.forEach { profile -> DropdownMenuItem(text = { Text(profile.name) }, onClick = { expanded = false; onSelect(profile.id) }) }
        }
    }
}

@Composable private fun DiagnosticsScreen(status: VpnStatus, saved: SavedSettings?) {
    Text(stringResource(R.string.local_state, phaseLabel(status.phase)), style = MaterialTheme.typography.titleMedium)
    Text(status.message)
    Text(stringResource(R.string.packet_counts, status.stats.sent, status.stats.received))
    status.servers.forEach { (id, server) ->
        val name = saved?.profiles?.firstOrNull { it.id == id }?.name ?: id
        Text("$name · ${connectionLabel(server.state)}", style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.packet_counts, server.stats.sent, server.stats.received))
        if (server.noResponse) Text(stringResource(R.string.no_server_reply))
    }
    Text(stringResource(R.string.direct_counts, status.directState?.let { connectionLabel(it) } ?: "—", status.direct.sent, status.direct.received))
    Text(stringResource(R.string.direct_details, status.direct.unavailable, status.direct.queueDrops,
        status.direct.rejectedReplies, status.direct.ambiguousOwner, status.direct.serverUnavailable))
    Text(stringResource(R.string.dns_counts, status.dns.pending, status.dns.completed, status.dns.timeouts))
    Text(stringResource(R.string.dns_details, status.dns.auxiliary, status.dns.malformed, status.dns.stale,
        status.dns.active, status.dns.expired, status.dns.ambiguous, status.dns.limits))
    Text(stringResource(R.string.drop_counts, status.stats.malformed, status.stats.fragments,
        status.stats.unknownEndpoint, status.stats.unknownFlow, status.stats.oversized, status.stats.queueDrops,
        status.unknownOwnerDrops))
}

@Composable private fun connectionLabel(state: ConnectionState) = when (state) {
    ConnectionState.WAITING_NETWORK -> stringResource(R.string.state_network_wait)
    ConnectionState.CONNECTING -> stringResource(R.string.state_connecting)
    ConnectionState.RETRYING -> stringResource(R.string.state_retrying)
    ConnectionState.RUNNING -> stringResource(R.string.state_running)
}

@Composable private fun phaseLabel(phase: Phase) = when (phase) {
    Phase.IDLE, Phase.STOPPED -> stringResource(R.string.tunnel_state_off)
    Phase.PREPARING -> stringResource(R.string.state_preparing)
    Phase.STARTING -> stringResource(R.string.state_connecting)
    Phase.RUNNING, Phase.REPLIED -> stringResource(R.string.state_running)
    Phase.PARTIAL -> stringResource(R.string.state_partial)
    Phase.NO_RESPONSE -> stringResource(R.string.no_server_reply)
    Phase.NETWORK_LOST, Phase.WAITING -> stringResource(R.string.state_network_wait)
    Phase.RETRYING -> stringResource(R.string.state_retrying)
    Phase.STOPPING -> stringResource(R.string.stopping)
    Phase.UNAVAILABLE -> stringResource(R.string.state_unavailable)
    Phase.REVOKED -> stringResource(R.string.state_revoked)
}
