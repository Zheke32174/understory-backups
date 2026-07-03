package com.understory.backups

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
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

        // Phase note — be honest about what's working today vs Wave B-2.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xFF332A14), RoundedCornerShape(6.dp))
                .padding(12.dp),
        ) {
            Text(
                "Working today: Android settings, user-dir manifest, full " +
                    "user-dir content backup (opt-in via the sub-toggle " +
                    "below; streamed to a .usbs companion file with " +
                    "chunked AES-GCM). Still pending: suite-app vaults " +
                    "and vault-folder secure files (need cross-app " +
                    "BackupContentProviders).",
                color = Color(0xFFFFB74D), fontSize = 11.sp,
            )
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
                    "Will snapshot Pictures / DCIM / Downloads / Documents / " +
                        "Music / Movies. Manifest (paths + sizes + first-" +
                        "64-KiB fingerprints) is always written. Full file " +
                        "contents are opt-in via the sub-toggle below — " +
                        "they go in a streaming-encrypted companion file " +
                        "(.usbs) bound to this snapshot's envelope."
                else "Needs READ_MEDIA_* permissions. Tap below to grant."
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

        SnapshotToggleRow(
            label = "Suite app vaults (passgen / aegis / …) — phase 2",
            description = "Stub. Each suite app needs a signature-locked " +
                "BackupContentProvider for cross-app dispatch. Until it " +
                "lands, this section emits a 'pending' note. Toggle stays " +
                "honest about what'll be there.",
            checked = cfg.includeSuiteAppVaults,
            onCheckedChange = {
                cfg = cfg.copy(includeSuiteAppVaults = it)
                DeviceSnapshotConfig.save(ctx, cfg)
            },
        )

        SnapshotToggleRow(
            label = "Vault-folder secure files — phase 2",
            description = "Same cross-app dispatch dependency as suite app " +
                "vaults. Stub for now.",
            checked = cfg.includeVaultFolderSecureFiles,
            onCheckedChange = {
                cfg = cfg.copy(includeVaultFolderSecureFiles = it)
                DeviceSnapshotConfig.save(ctx, cfg)
            },
        )

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
            Text(
                "External: ${cfg.destinationTreeUri}",
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
                status = "Snapshot started. Watch the foreground notification " +
                    "for progress; the result lands in your destination."
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

private fun currentMediaPermissionsToRequest(): Array<String> {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        arrayOf(
            Manifest.permission.READ_MEDIA_IMAGES,
            Manifest.permission.READ_MEDIA_VIDEO,
            Manifest.permission.READ_MEDIA_AUDIO,
        )
    } else {
        arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
    }
}
