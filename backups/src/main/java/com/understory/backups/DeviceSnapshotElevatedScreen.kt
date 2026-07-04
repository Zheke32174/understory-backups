package com.understory.backups

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.understory.elevation.Outcome
import com.understory.elevation.ui.ElevationCard
import com.understory.elevation.ui.rememberElevationState
import com.understory.security.Diagnostics
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.Bg
import com.understory.security.ui.components.ConfirmDestructiveDialog
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.components.SwitchRow
import com.understory.security.ui.theme.UnderstoryTheme
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * "Device snapshot (elevated)" — the app's FIRST elevated feature.
 *
 * Captures device POSTURE (installed-app inventory + a benign allowlisted
 * settings set) via READ-ONLY shell reads, persists it as plain JSON in private
 * storage, and offers two guided restore modes: a reinstall CHECKLIST (never a
 * silent reinstall) and per-key, diff-shown, opt-in settings writes.
 *
 * Fail-closed & honest by construction:
 *  - When [Elevation.canRunShell] is false the whole elevated surface is replaced
 *    by the shared [ElevationCard] grant invite — no dead/greyed capture button.
 *  - Read parses degrade OPEN: a dump-format drift yields fewer fields, never a
 *    crash or a fabricated value.
 *  - The only WRITE path (settings restore) is per-key opt-in behind a diff and
 *    surfaces per-key [Outcome.Failed] rejections verbatim.
 *
 * Complementary to the self-sealing envelope: this is device posture, NOT vault
 * data. The [vault] param is threaded for route symmetry with the other backup
 * screens; posture capture needs no vault secret and renders none.
 */
@Composable
fun DeviceSnapshotElevatedScreen(
    @Suppress("UNUSED_PARAMETER") vault: UnlockedBackupsVault,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current

    // Reactive elevation state. The shared ElevationCard drives its own grant
    // refresh internally; we read the reactive isElevated to gate the surface.
    val elev = rememberElevationState()

    SuiteScaffold(
        title = stringResource(R.string.snapshot_title),
        onBack = onBack,
        showSuiteFooter = false,
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .verticalScroll(rememberScrollState())
                .padding(UnderstoryTheme.spacing.lg),
            verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
        ) {
            Text(
                stringResource(R.string.snapshot_intro),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (!elev.isElevated) {
                // Fail-closed: no dead capture control. Route to the grant flow.
                ElevationCard(
                    unlocks = listOf(
                        stringResource(R.string.snapshot_unlock_inventory),
                        stringResource(R.string.snapshot_unlock_settings),
                    ),
                    rootlessFallback = stringResource(R.string.snapshot_rootless_fallback),
                )
            } else {
                ElevatedSnapshotBody(ctx = ctx)
            }
        }
    }
}

/**
 * The elevated body: capture trigger + progress, the persisted-snapshot list,
 * and the two guided restore surfaces for the selected snapshot.
 */
@Composable
private fun ElevatedSnapshotBody(ctx: Context) {
    val scope = rememberCoroutineScope()

    var headers by remember { mutableStateOf(SnapshotCapture.headers(ctx)) }
    var capturing by remember { mutableStateOf(false) }
    var progress by remember { mutableStateOf<SnapshotCapture.Progress?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var statusError by remember { mutableStateOf(false) }

    // The snapshot the user has opened for restore (loaded lazily on tap).
    var opened by remember { mutableStateOf<SnapshotCapture.Snapshot?>(null) }

    fun refreshHeaders() { headers = SnapshotCapture.headers(ctx) }

    SuiteSectionHeader(stringResource(R.string.snapshot_capture_header))
    SuiteCard {
        Text(
            stringResource(R.string.snapshot_capture_body),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        if (capturing) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                val p = progress
                Text(
                    if (p == null) stringResource(R.string.snapshot_capturing)
                    else "${p.phase} ${p.done}/${p.total}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            SecureOutlinedButton(
                onClick = {
                    capturing = true
                    status = null
                    progress = null
                    scope.launch {
                        val snap = withContext(Bg.io) {
                            SnapshotCapture.capture(ctx) { p -> progress = p }
                        }
                        val file = withContext(Bg.io) { SnapshotCapture.save(ctx, snap) }
                        capturing = false
                        progress = null
                        if (file != null) {
                            status = ctx.getString(
                                R.string.snapshot_capture_ok,
                                snap.packages.size,
                                snap.settings.size,
                            )
                            statusError = false
                            refreshHeaders()
                        } else {
                            status = ctx.getString(R.string.snapshot_capture_save_failed)
                            statusError = true
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Filled.CameraAlt, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                Text(stringResource(R.string.snapshot_capture_now))
            }
        }
        status?.let {
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (statusError) MaterialTheme.colorScheme.error
                else UnderstoryTheme.semantic.success,
            )
        }
    }

    // ---- Saved snapshots list ----
    SuiteSectionHeader(
        stringResource(R.string.snapshot_saved_header, headers.size),
    )
    if (headers.isEmpty()) {
        Text(
            stringResource(R.string.snapshot_none_yet),
            style = MaterialTheme.typography.bodyMedium,
            color = UnderstoryTheme.semantic.dim,
        )
    } else {
        headers.forEach { h ->
            var confirmDelete by remember(h.file.path) { mutableStateOf(false) }
            SuiteListRow(
                headline = h.formattedTimestamp(),
                supporting = stringResource(
                    R.string.snapshot_saved_sub, h.packageCount, h.settingCount,
                ),
                leading = {
                    Icon(
                        Icons.Filled.Restore,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                    )
                },
                onClick = {
                    scope.launch {
                        val loaded = withContext(Bg.io) { SnapshotCapture.load(h.file) }
                        opened = loaded
                        if (loaded == null) {
                            status = ctx.getString(R.string.snapshot_open_failed)
                            statusError = true
                        }
                    }
                },
                trailing = {
                    SecureOutlinedButton(onClick = { confirmDelete = true }) {
                        Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.snapshot_delete), modifier = Modifier.size(16.dp))
                    }
                },
            )
            ConfirmDestructiveDialog(
                visible = confirmDelete,
                title = stringResource(R.string.snapshot_delete_title),
                body = stringResource(R.string.snapshot_delete_body, h.formattedTimestamp()),
                confirmLabel = stringResource(R.string.snapshot_delete),
                requireHold = true,
                onConfirm = {
                    confirmDelete = false
                    SnapshotCapture.delete(h.file)
                    if (opened != null) opened = null
                    refreshHeaders()
                },
                onDismiss = { confirmDelete = false },
            )
        }
    }

    // ---- Guided restore for the opened snapshot ----
    opened?.let { snap ->
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        GuidedReinstallSection(ctx, snap)
        SettingsRestoreSection(ctx, snap)
    }
}

/**
 * App-inventory guided restore — a CHECKLIST, never a silent reinstall. Lists
 * the captured packages not currently installed (suite siblings / launcher /
 * settings / Tailscale / Shizuku excluded) with a per-app "Open in store" link.
 */
@Composable
private fun GuidedReinstallSection(ctx: Context, snapshot: SnapshotCapture.Snapshot) {
    val missing = remember(snapshot) { SnapshotRestore.missingApps(ctx, snapshot) }

    SuiteSectionHeader(stringResource(R.string.snapshot_reinstall_header))
    SuiteCard {
        Text(
            stringResource(R.string.snapshot_reinstall_body),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
    }
    if (missing.isEmpty()) {
        Text(
            stringResource(R.string.snapshot_reinstall_none),
            style = MaterialTheme.typography.bodyMedium,
            color = UnderstoryTheme.semantic.success,
        )
        return
    }
    missing.forEach { app ->
        SuiteListRow(
            headline = app.packageName,
            supporting = app.versionName?.let {
                stringResource(R.string.snapshot_reinstall_ver, it)
            },
            leading = {
                Icon(
                    Icons.Filled.Apps,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                )
            },
            trailing = {
                SecureOutlinedButton(onClick = { openInStore(ctx, app.packageName) }) {
                    Icon(Icons.Filled.OpenInNew, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(UnderstoryTheme.spacing.xs))
                    Text(stringResource(R.string.snapshot_reinstall_store))
                }
            },
        )
    }
}

/**
 * Settings restore — per-key opt-in with a live diff and honest per-key results.
 * Only the small [SnapshotRestore.RESTORABLE_KEYS] set is writable; each write
 * shows Success / Unsupported / Failed inline.
 */
@Composable
private fun SettingsRestoreSection(ctx: Context, snapshot: SnapshotCapture.Snapshot) {
    val scope = rememberCoroutineScope()
    var diffs by remember(snapshot) { mutableStateOf<List<SnapshotRestore.SettingDiff>?>(null) }
    // Per-key result line, keyed by "ns/key".
    val results = remember(snapshot) { androidx.compose.runtime.mutableStateMapOf<String, Pair<String, Boolean>>() }
    // Per-key opt-in selection.
    val selected = remember(snapshot) { androidx.compose.runtime.mutableStateMapOf<String, Boolean>() }

    androidx.compose.runtime.LaunchedEffect(snapshot) {
        diffs = withContext(Bg.io) { SnapshotRestore.settingsDiff(ctx, snapshot) }
    }

    SuiteSectionHeader(stringResource(R.string.snapshot_settings_header))
    SuiteCard {
        Text(
            stringResource(R.string.snapshot_settings_body),
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
    }

    val list = diffs
    when {
        list == null -> {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                Text(
                    stringResource(R.string.snapshot_settings_reading),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        list.isEmpty() -> {
            Text(
                stringResource(R.string.snapshot_settings_none),
                style = MaterialTheme.typography.bodyMedium,
                color = UnderstoryTheme.semantic.dim,
            )
        }
        else -> {
            list.forEach { diff ->
                val id = "${diff.meta.namespace}/${diff.meta.key}"
                val sub = if (diff.changed) {
                    stringResource(
                        R.string.snapshot_settings_diff,
                        diff.currentValue ?: stringResource(R.string.snapshot_settings_unset),
                        diff.capturedValue,
                    )
                } else {
                    stringResource(R.string.snapshot_settings_same, diff.capturedValue)
                }
                SuiteCard {
                    SwitchRow(
                        label = "${diff.meta.label} (${diff.meta.namespace})",
                        checked = selected[id] == true,
                        onCheckedChange = { selected[id] = it },
                        supporting = sub,
                        enabled = diff.changed,
                    )
                    results[id]?.let { (line, err) ->
                        Text(
                            line,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (err) MaterialTheme.colorScheme.error
                            else UnderstoryTheme.semantic.success,
                        )
                    }
                }
            }

            val anySelected = list.any { selected["${it.meta.namespace}/${it.meta.key}"] == true }
            SecureOutlinedButton(
                onClick = {
                    scope.launch {
                        for (diff in list) {
                            val id = "${diff.meta.namespace}/${diff.meta.key}"
                            if (selected[id] != true) continue
                            val outcome = withContext(Bg.io) { SnapshotRestore.restoreSetting(ctx, diff) }
                            results[id] = when (outcome) {
                                is Outcome.Success ->
                                    ctx.getString(R.string.snapshot_settings_result_ok) to false
                                is Outcome.Unsupported ->
                                    ctx.getString(R.string.snapshot_settings_result_unsupported, outcome.reason) to true
                                is Outcome.Failed ->
                                    ctx.getString(R.string.snapshot_settings_result_failed, outcome.message) to true
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Filled.Tune, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                Text(
                    if (anySelected) stringResource(R.string.snapshot_settings_apply)
                    else stringResource(R.string.snapshot_settings_apply_hint),
                )
            }
        }
    }
}

/**
 * Open the app's store page so the USER can reinstall it. Tries the store deep
 * link first, falling back to an https store URL. We never install; we only
 * hand the user to the store.
 */
private fun openInStore(ctx: Context, pkg: String) {
    val tryLaunch: (Uri) -> Boolean = { uri ->
        runCatching {
            ctx.startActivity(
                Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            true
        }.getOrElse { false }
    }
    Diagnostics.log("backups.SnapshotRestore", "open store for $pkg")
    if (tryLaunch(Uri.parse("market://details?id=$pkg"))) return
    if (!tryLaunch(Uri.parse("https://play.google.com/store/apps/details?id=$pkg"))) {
        Diagnostics.error("backups.SnapshotRestore", "no store activity for $pkg")
    }
}
