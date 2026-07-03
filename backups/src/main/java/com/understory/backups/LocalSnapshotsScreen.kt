package com.understory.backups

import android.net.Uri
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.understory.security.Diagnostics
import com.understory.security.ui.components.ConfirmDestructiveDialog

/**
 * Browse + restore + delete locally-saved snapshots.
 *
 * The snapshot store ([LocalSnapshotStore]) is private to this app's
 * filesDir, so peer apps can't enumerate or read these files. The list
 * here is read fresh on every recomposition triggered by [refreshKey] —
 * we don't observe filesystem changes, so a snapshot saved from another
 * activity won't appear until the user navigates back into this screen.
 *
 * Restore writes the decrypted plaintext to a SAF-picked location. We
 * deliberately don't auto-restore into the source app — the current
 * suite contract has each app import its own plaintext payload via its
 * own UI (cross-app dispatch would require a signature-locked content
 * provider per app, which is the next chunk of work).
 */
@Composable
fun LocalSnapshotsScreen(vault: UnlockedBackupsVault, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var refreshKey by remember { mutableStateOf(0) }
    val snapshots = remember(refreshKey) { LocalSnapshotStore.list(ctx) }
    var status by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    var pendingRestore by remember { mutableStateOf<LocalSnapshotStore.Info?>(null) }
    // Delete requires an explicit confirm (D-14): no one-tap destructive action.
    var pendingDelete by remember { mutableStateOf<LocalSnapshotStore.Info?>(null) }
    var keepLast by remember { mutableStateOf(LocalSnapshotStore.retentionKeepLast(ctx)) }

    // SAF createDocument for the restore output. We launch it on demand
    // from the per-row "Restore" button; the callback then drives the
    // actual decrypt against [pendingRestore].
    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri: Uri? ->
        BackupsVaultManager.endTransientFlight()
        val target = pendingRestore
        pendingRestore = null
        if (uri == null || target == null) return@rememberLauncherForActivityResult
        working = true
        val keyChars = vault.recoveryChars()
        val result = BackupsFlow.decryptLocalSnapshot(
            ctx = ctx,
            snapshotFile = target.file,
            outputUri = uri,
            passphrase = keyChars,
        )
        status = when (result) {
            is BackupsFlow.Result.Success -> result.message
            is BackupsFlow.Result.Failure -> result.message
        }
        Toast.makeText(ctx, status, Toast.LENGTH_LONG).show()
        working = false
    }

    // Delete-confirm dialog (D-14). Uses the shared destructive confirm.
    pendingDelete?.let { target ->
        ConfirmDestructiveDialog(
            visible = true,
            title = "Delete this snapshot?",
            body = "This permanently removes \"${target.userLabel.ifEmpty { "(no label)" }}\" " +
                "from this device. This cannot be undone. Any copy you already " +
                "exported elsewhere is unaffected.",
            confirmLabel = "Delete",
            onConfirm = {
                Diagnostics.log("backups.LocalSnapshots", "delete confirmed: ${target.file.name}")
                status = if (LocalSnapshotStore.delete(target.file)) {
                    refreshKey++; "Deleted ${target.file.name}."
                } else "Couldn't delete ${target.file.name}."
                pendingDelete = null
            },
            onDismiss = { pendingDelete = null },
        )
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("local snapshots", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Encrypted backups saved to this device's private storage. " +
                "Each snapshot is an AES-256-GCM envelope; the master key " +
                "comes from the unlocked vault. Tap Restore to decrypt to a " +
                "user-chosen location, or Delete to remove the snapshot.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )

        // Retention (D-15 / A-10): the "keep last N" policy the local-save
        // paths apply. Off keeps everything.
        RetentionRow(
            keepLast = keepLast,
            onChange = { newKeep ->
                keepLast = newKeep
                LocalSnapshotStore.setRetentionKeepLast(ctx, newKeep)
                // Apply immediately so an existing overflow is pruned now.
                LocalSnapshotStore.applyRetention(ctx)
                refreshKey++
            },
        )

        if (snapshots.isEmpty()) {
            // Empty state fills the remaining space so Back stays pinned.
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .background(Color(0xFF141414), RoundedCornerShape(6.dp))
                    .padding(20.dp),
            ) {
                Text(
                    "No snapshots yet. From the Encrypt screen, pick an input " +
                        "file and tap \"Encrypt → save snapshot on this device\".",
                    color = Color(0xFF707070), fontSize = 12.sp,
                )
            }
        } else {
            Text(
                "${snapshots.size} snapshot${if (snapshots.size == 1) "" else "s"}",
                color = Color(0xFF707070), fontSize = 11.sp,
            )
            // weight(1f) so the list scrolls INSIDE the screen and the status
            // line + Back below can never be pushed off (D-11).
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth().weight(1f),
            ) {
                items(snapshots, key = { it.file.absolutePath }) { info ->
                    SnapshotRow(
                        info = info,
                        working = working,
                        onRestore = {
                            Diagnostics.log("backups.LocalSnapshots",
                                "restore tap: ${info.file.name}")
                            pendingRestore = info
                            BackupsVaultManager.beginTransientFlight()
                            runCatching {
                                createOutput.launch(
                                    "${info.appLabel}-restored-${info.formattedTimestamp().replace(' ', '_')}.bin"
                                )
                            }.onFailure {
                                BackupsVaultManager.endTransientFlight()
                                pendingRestore = null
                                status = "Couldn't open output picker: ${it.message}"
                            }
                        },
                        onDelete = {
                            Diagnostics.log("backups.LocalSnapshots",
                                "delete tap: ${info.file.name}")
                            pendingDelete = info
                        },
                    )
                }
            }
        }

        status?.let {
            Text(
                it,
                color = if (it.startsWith("Decrypted") || it.startsWith("Deleted"))
                    Color(0xFF81C784) else Color(0xFFFFB74D),
                fontSize = 12.sp,
            )
        }

        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
            Text("Back")
        }
    }
}

@Composable
private fun RetentionRow(
    keepLast: Int,
    onChange: (Int) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
    ) {
        Text("Keep last:", color = Color(0xFF9E9E9E), fontSize = 12.sp)
        LocalSnapshotStore.RETENTION_CHOICES.forEach { choice ->
            val selected = choice == keepLast
            OutlinedButton(
                onClick = { onChange(choice) },
                modifier = Modifier.weight(1f),
            ) {
                Text(
                    if (choice == 0) "Off" else "$choice",
                    color = if (selected) Color(0xFF81C784) else Color(0xFFE0E0E0),
                    fontSize = 12.sp,
                )
            }
        }
    }
}

@Composable
private fun SnapshotRow(
    info: LocalSnapshotStore.Info,
    working: Boolean,
    onRestore: () -> Unit,
    onDelete: () -> Unit,
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
            .padding(12.dp),
    ) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Text(
                info.userLabel.ifEmpty { "(no label)" },
                color = Color(0xFFE0E0E0), fontSize = 13.sp,
            )
            Text(
                "${info.appLabel} · ${info.formattedTimestamp()} · " +
                    "${info.sizeBytes / 1024} KiB",
                color = Color(0xFF9E9E9E), fontSize = 11.sp,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick = onRestore,
                    enabled = !working,
                    modifier = Modifier.fillMaxWidth(0.6f),
                ) { Text("Restore") }
                OutlinedButton(
                    onClick = onDelete,
                    enabled = !working,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Delete") }
            }
        }
    }
}
