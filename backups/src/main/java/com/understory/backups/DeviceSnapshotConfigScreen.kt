package com.understory.backups

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.security.Diagnostics

/**
 * Device-wide snapshot configuration. Toggles per section, destination
 * picker, and "Snapshot now" trigger. Reads + writes
 * [DeviceSnapshotConfig] via SharedPreferences; on tap, hands the
 * unlocked vault's recovery chars to [DeviceSnapshotService] which
 * does the actual collect+encrypt+write off the main thread.
 *
 * Permission flow for [DeviceSnapshotConfig.includeStandardUserDirs]:
 *   - Android 13+: request READ_MEDIA_IMAGES, READ_MEDIA_VIDEO,
 *     READ_MEDIA_AUDIO together via OpenMultiplePermissions contract.
 *   - Android 12-: request READ_EXTERNAL_STORAGE.
 *   - Either way: granted permissions persist; we read them back on
 *     each entry and label the toggle accordingly.
 *   - If the user denies, the toggle stays on but the collector emits
 *     status="permission_denied" sections. Honest-vs-silent behavior.
 */
@Composable
fun DeviceSnapshotConfigScreen(
    vault: UnlockedBackupsVault,
    onBack: () -> Unit,
) {
    val ctx = LocalContext.current
    var cfg by remember { mutableStateOf(DeviceSnapshotConfig.load(ctx)) }
    var status by remember { mutableStateOf<String?>(null) }

    // Track media-permission state so the user-dirs toggle can show
    // "(needs permission)" honestly. Re-checked after the permission
    // launcher returns.
    var hasMediaPerms by remember { mutableStateOf(checkMediaPermissions(ctx)) }
    val mediaPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { grants ->
        Diagnostics.log("backups.DeviceSnapshotConfig",
            "media perm result: granted=${grants.count { it.value }}/${grants.size}")
        hasMediaPerms = checkMediaPermissions(ctx)
    }

    // POST_NOTIFICATIONS runtime state (backups.md §6). On minSdk 33 this is
    // always a runtime prompt; if denied, the FGS still runs and the in-app
    // status row carries progress instead.
    var hasNotifPerm by remember { mutableStateOf(checkNotifPermission(ctx)) }
    val notifPermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        Diagnostics.log("backups.DeviceSnapshotConfig", "notif perm result: granted=$granted")
        hasNotifPerm = checkNotifPermission(ctx)
    }

    // SAF tree picker for choosing an external destination directory.
    // OpenDocumentTree returns a tree URI; we takePersistableUriPermission
    // so writes survive process restart.
    val treePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            val flags = android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION or
                android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            ctx.contentResolver.takePersistableUriPermission(uri, flags)
        }.onFailure {
            Diagnostics.error("backups.DeviceSnapshotConfig",
                "takePersistableUriPermission threw: ${it.message}")
        }
        cfg = cfg.copy(destinationTreeUri = uri.toString())
        DeviceSnapshotConfig.save(ctx, cfg)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("device snapshot", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Captures a point-in-time snapshot of your device's user-side " +
                "state, encrypted under the unlocked vault's master key. No " +
                "system apps, no protected/system settings, no other apps' " +
                "private storage (Android sandbox prevents reading those " +
                "anyway). Per-section toggles below.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )

        // Notification honesty (backups.md §6, A-14/D-1): the FGS posts
        // progress notifications, but on minSdk 33 they are silently dropped
        // unless POST_NOTIFICATIONS is granted at runtime. We request it here
        // before the snapshot can run, and degrade honestly (the in-app
        // status line below carries progress) if the user denies.
        if (!hasNotifPerm) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xFF332A14), RoundedCornerShape(6.dp))
                    .padding(12.dp),
            ) {
                Text(
                    "Notifications off — snapshot progress will show on this " +
                        "screen while it runs. Grant notifications to watch " +
                        "progress after you navigate away.",
                    color = Color(0xFFFFB74D), fontSize = 11.sp,
                )
            }
            OutlinedButton(
                onClick = { notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Grant notification permission") }
        }

        Spacer(Modifier.height(4.dp))

        // ---------- Section toggles ----------
        SnapshotToggleRow(
            label = "Android settings",
            description = if (cfg.includeAndroidSettings)
                "Will capture user-tunable Settings.System / Settings.Secure / " +
                    "Settings.Global keys. Most security-sensitive keys are " +
                    "system-protected and skipped honestly."
            else "Skipped.",
            checked = cfg.includeAndroidSettings,
            onCheckedChange = {
                cfg = cfg.copy(includeAndroidSettings = it)
                DeviceSnapshotConfig.save(ctx, cfg)
            },
        )

        SnapshotToggleRow(
            label = if (hasMediaPerms) "Standard user dirs"
                else "Standard user dirs — needs permission",
            description = if (cfg.includeStandardUserDirs) {
                if (hasMediaPerms)
                    "Coverage: photos, videos and audio (the media library) " +
                        "under Pictures / DCIM / Downloads / Documents / Music / " +
                        "Movies. NON-media files other apps saved to Documents or " +
                        "Downloads are not visible to a rootless app via the media " +
                        "grant — pick those with a folder grant (coming) for full " +
                        "coverage. Manifest (paths + sizes + first-64-KiB " +
                        "fingerprints) is always written; full file contents are " +
                        "opt-in via the sub-toggle below (streamed to a .usbs " +
                        "companion file bound to this snapshot's envelope)."
                else "Needs media permissions. Tap below to grant."
            } else "Skipped.",
            checked = cfg.includeStandardUserDirs,
            onCheckedChange = {
                cfg = cfg.copy(includeStandardUserDirs = it)
                DeviceSnapshotConfig.save(ctx, cfg)
                if (it && !hasMediaPerms) {
                    mediaPermLauncher.launch(currentMediaPermissionsToRequest())
                }
            },
        )
        if (cfg.includeStandardUserDirs) {
            // Sub-toggle: full content backup. Off by default because
            // a full Pictures+Music dump is multi-GiB and the user
            // should pick a SAF tree URI destination first to avoid
            // hitting the app's internal-storage quota.
            SnapshotToggleRow(
                label = "    + Include file contents (multi-GiB possible)",
                description = if (cfg.includeUserDirContent)
                    "Full content streamed to device-<ts>.usbs alongside " +
                        "the JSON envelope. Memory cost bounded; total " +
                        "size bounded only by destination free space. " +
                        "Recommend an external SAF directory."
                else "Manifest only (paths + sizes + fingerprints).",
                checked = cfg.includeUserDirContent,
                onCheckedChange = {
                    cfg = cfg.copy(includeUserDirContent = it)
                    DeviceSnapshotConfig.save(ctx, cfg)
                },
            )
        }
        if (cfg.includeStandardUserDirs && !hasMediaPerms) {
            OutlinedButton(
                onClick = { mediaPermLauncher.launch(currentMediaPermissionsToRequest()) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Grant media permissions") }
        }

        // Suite-app-vault and vault-folder-secure-file sections are HIDDEN
        // (backups.md §10, D-13): they had no real data and wrote a "pending"
        // stub. The honest home for peer exports is the deposit-intent collect
        // screen (§3), not a dead toggle here. When §3 lands, a "Collect suite
        // exports" entry appears instead. Their config flags default OFF.

        Spacer(Modifier.height(8.dp))

        // ---------- Destination ----------
        Text("Destination", color = Color(0xFFE0E0E0), fontSize = 14.sp)
        if (cfg.destinationTreeUri == null) {
            Text(
                "Internal storage (filesDir/snapshots/). No size cap from " +
                    "us, but the OS bounds your app's quota. Choose an " +
                    "external folder for multi-GB snapshots once full-content " +
                    "backup ships.",
                color = Color(0xFF9E9E9E), fontSize = 11.sp,
            )
        } else {
            // Readable destination name (D-17), not the raw content://…%3A… URI.
            val destName = remember(cfg.destinationTreeUri) {
                friendlyTreeName(ctx, cfg.destinationTreeUri)
            }
            Text(
                "External folder: $destName",
                color = Color(0xFF9E9E9E), fontSize = 11.sp,
            )
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = { treePicker.launch(null) },
                modifier = Modifier.weight(1f),
            ) { Text(if (cfg.destinationTreeUri == null) "Pick external dir" else "Change external dir") }
            if (cfg.destinationTreeUri != null) {
                OutlinedButton(
                    onClick = {
                        cfg = cfg.copy(destinationTreeUri = null)
                        DeviceSnapshotConfig.save(ctx, cfg)
                    },
                    modifier = Modifier.weight(1f),
                ) { Text("Use internal") }
            }
        }

        Spacer(Modifier.height(12.dp))

        // ---------- Trigger ----------
        Button(
            onClick = {
                if (!cfg.anyEnabled) {
                    status = "Toggle at least one section before snapshotting."
                    return@Button
                }
                Diagnostics.log("backups.DeviceSnapshotConfig", "Snapshot now: tap")
                val passphrase = vault.recoveryChars()
                DeviceSnapshotService.start(ctx, passphrase)
                status = if (hasNotifPerm) {
                    "Snapshot started. Watch the notification for progress; " +
                        "the result lands in your destination."
                } else {
                    "Snapshot started. Notifications are off, so progress " +
                        "shows here while this screen is open; the result " +
                        "lands in your destination."
                }
                Toast.makeText(ctx, "Snapshot started", Toast.LENGTH_SHORT).show()
            },
            enabled = cfg.anyEnabled,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Snapshot now") }

        status?.let {
            Text(
                it,
                color = if (it.startsWith("Snapshot started")) Color(0xFF81C784)
                    else Color(0xFFFFB74D),
                fontSize = 12.sp,
            )
        }

        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text("Back")
        }
    }
}

@Composable
private fun SnapshotToggleRow(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.fillMaxWidth(0.85f)) {
            Text(label, color = Color(0xFFE0E0E0), fontSize = 13.sp)
            Text(description, color = Color(0xFF9E9E9E), fontSize = 11.sp)
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

private fun checkMediaPermissions(ctx: Context): Boolean {
    val perms = currentMediaPermissionsToRequest()
    return perms.all {
        ctx.checkCallingOrSelfPermission(it) == PackageManager.PERMISSION_GRANTED
    }
}

/**
 * minSdk is 33, so the per-type READ_MEDIA_* set is the only path (the pre-13
 * READ_EXTERNAL_STORAGE fallback branch is deleted — D-15). These back only the
 * "Add media libraries" convenience source; arbitrary-folder backup uses SAF
 * tree grants and needs no manifest permission.
 */
private fun currentMediaPermissionsToRequest(): Array<String> = arrayOf(
    Manifest.permission.READ_MEDIA_IMAGES,
    Manifest.permission.READ_MEDIA_VIDEO,
    Manifest.permission.READ_MEDIA_AUDIO,
)

private fun checkNotifPermission(ctx: Context): Boolean =
    ctx.checkCallingOrSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
        PackageManager.PERMISSION_GRANTED

/**
 * Human-readable name for a persisted SAF tree URI (D-17): the DocumentFile
 * display name, falling back to the last decoded path segment, never the raw
 * `content://…%3A…` string.
 */
private fun friendlyTreeName(ctx: Context, treeUri: String?): String {
    if (treeUri == null) return "(none)"
    return runCatching {
        val uri = android.net.Uri.parse(treeUri)
        val name = androidx.documentfile.provider.DocumentFile
            .fromTreeUri(ctx, uri)?.name
        if (!name.isNullOrBlank()) return@runCatching name
        // Fall back to the decoded document-id tail (e.g. "primary:Backups").
        val decoded = android.net.Uri.decode(uri.lastPathSegment ?: "")
        decoded.substringAfterLast(':').ifBlank { decoded }.ifBlank { "external folder" }
    }.getOrDefault("external folder")
}
