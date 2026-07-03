package com.understory.backups

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.understory.backup.AesGcmPassphraseCodec
import com.understory.backup.BackupEnvelope
import com.understory.backup.StreamingAesGcmCodec
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service that produces a device-wide snapshot.
 *
 * Trigger: started by [DeviceSnapshotConfigScreen] once the user taps
 * "Snapshot now" with at least one section enabled. Service reads the
 * persisted [DeviceSnapshotConfig] and the master key from the
 * unlocked vault (vault must already be unlocked when the service
 * starts — caller is responsible for that contract).
 *
 * Pipeline:
 *
 *   1. Build a JSON document with one top-level key per ENABLED
 *      section. Working sections fill in real data; stubbed sections
 *      get a "status: pending" stub explaining the Wave B-2 cross-app
 *      provider dependency.
 *
 *   2. Encrypt the whole JSON via AesGcmPassphraseCodec under the
 *      passphrase derived from the unlocked master KEK (passed in via
 *      the start intent's extra — service doesn't unlock the vault
 *      itself).
 *
 *   3. Write the resulting envelope:
 *      - if config.destinationTreeUri is null: filesDir/snapshots/
 *        device-<UTC-ISO>.usbe via FileOutputStream
 *      - else: into the SAF tree URI, named device-<UTC-ISO>.usbe,
 *        via DocumentsContract.createDocument
 *
 *   4. Foreground notification updates after each section completes
 *      and posts a final "Snapshot saved" / "Snapshot failed" line.
 *
 * Why not WorkManager: the snapshot is user-initiated (one tap) and
 * needs to run NOW with a visible progress indicator. WorkManager's
 * scheduling overhead doesn't fit. A FGS gives us the same survival
 * guarantee (process stays alive across user navigation) without the
 * scheduling layer.
 *
 * Threat model: the master passphrase (vault recovery chars) is
 * passed via Intent extra as a CharArray. Intents traverse the
 * system's binder pipe; an attacker on the device with shell access
 * could read it. We accept this trade-off for the foreground-service
 * activation pattern. Alternative (in-process bound service) adds a
 * fragile lifecycle without changing the threat surface meaningfully —
 * the same chars would have to land in this service's heap either way.
 */
class DeviceSnapshotService : Service() {

    private val running = AtomicBoolean(false)
    private var workerThread: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ID,
                buildNotification("Preparing snapshot…", null),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(NOTIF_ID, buildNotification("Preparing snapshot…", null))
        }

        if (intent?.action == ACTION_STOP) {
            running.set(false)
            workerThread?.interrupt()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        if (running.get()) {
            // Already running. Ignore re-start requests; user can stop
            // first if they want to re-run with different config.
            Diagnostics.log("backups.DeviceSnapshotService",
                "ignoring start: already running")
            return START_NOT_STICKY
        }

        val passphrase = intent?.getCharArrayExtra(EXTRA_PASSPHRASE)
        if (passphrase == null || passphrase.isEmpty()) {
            Diagnostics.error("backups.DeviceSnapshotService",
                "missing or empty EXTRA_PASSPHRASE")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        running.set(true)
        workerThread = Thread({
            try {
                runSnapshot(passphrase)
            } finally {
                Crypto.wipe(passphrase)
                running.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }, "device-snapshot-worker").also { it.start() }

        return START_NOT_STICKY
    }

    override fun onDestroy() {
        running.set(false)
        workerThread?.interrupt()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun runSnapshot(passphrase: CharArray) {
        val cfg = DeviceSnapshotConfig.load(this)
        val payload = JSONObject().apply {
            put("schema", "device-snapshot.v1")
            put("device_id", android.os.Build.FINGERPRINT)
            put("created_at_ms", System.currentTimeMillis())
        }

        if (cfg.includeAndroidSettings) {
            updateNotification("Collecting Android settings…")
            payload.put("android_settings",
                JSONObject(AndroidSettingsCollector.collect(this)))
        }

        if (cfg.includeStandardUserDirs) {
            updateNotification("Collecting user-dir manifest…")
            // PERMISSION CAVEAT: caller (the launching screen) is
            // responsible for the runtime permission flow. If we don't
            // have READ_MEDIA_*, the collector returns empty per-section
            // entries with status="permission_denied" rather than
            // crashing. The user sees the result in the snapshot.
            payload.put("user_dirs_manifest",
                JSONObject(UserDirsManifestCollector.collect(this)))
            // Manifest is always emitted; full content is opt-in via
            // includeUserDirContent (handled below in the streaming
            // companion-file write). Manifest's first-64KiB SHA-256
            // fingerprints let the restore tool dedupe content
            // entries against existing files even if the .usbs is
            // unavailable at restore time.
            payload.put("user_dirs_content_status",
                if (cfg.includeUserDirContent) "stream-companion-file"
                else "manifest-only (opt-in: includeUserDirContent)"
            )
        }

        if (cfg.includeSuiteAppVaults) {
            // Stubbed: needs a signature-locked BackupContentProvider
            // in each suite app. Tracked as Wave B-2.
            payload.put("suite_app_vaults", JSONObject().apply {
                put("status", "pending")
                put("reason",
                    "Wave B-2: each suite app needs a signature-locked " +
                        "BackupContentProvider that exposes its " +
                        "BackupAdapter.export(). Once that lands, this " +
                        "section will contain {passgen, aegis, ...} " +
                        "vault snapshots inline."
                )
            })
        }

        if (cfg.includeVaultFolderSecureFiles) {
            payload.put("vault_folder_secure_files", JSONObject().apply {
                put("status", "pending")
                put("reason",
                    "Wave B-2: vault-folder needs the same cross-app " +
                        "BackupContentProvider so this snapshot can pull " +
                        "its encrypted blobs without a manual export step."
                )
            })
        }

        updateNotification("Encrypting + writing…")
        val plaintext = payload.toString().toByteArray(Charsets.UTF_8)
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }.format(Date())
        val createdAtMs = System.currentTimeMillis()
        val header = BackupEnvelope.Header(
            appId = "com.understory.backups.device-snapshot",
            schemaVersion = 1,
            createdAtMs = createdAtMs,
            label = "device-snapshot",
            codecParams = emptyMap(),
        )
        try {
            val key = AesGcmPassphraseCodec.PassphraseKey(passphrase.copyOf())
            try {
                writeEnvelope(cfg.destinationTreeUri, ts, header, plaintext, key)
            } finally {
                key.wipe()
            }

            // Phase 2: when the user opted in, write the streaming-
            // encrypted user-dir content blob alongside the envelope.
            // Bound to the envelope via an external-AAD derived from
            // the Header fields, so a stream pulled from one snapshot
            // can't be transplanted under another's envelope.
            if (cfg.includeStandardUserDirs && cfg.includeUserDirContent) {
                updateNotification("Streaming user-dir content…")
                writeContentStream(cfg.destinationTreeUri, ts, header, passphrase)
            }

            updateNotification("Snapshot saved.", complete = true)
            Diagnostics.log("backups.DeviceSnapshotService",
                "snapshot ok: ${plaintext.size} bytes" +
                    (if (cfg.includeUserDirContent) " (+ content stream)" else ""))
        } catch (t: Throwable) {
            Diagnostics.error("backups.DeviceSnapshotService",
                "snapshot failed: ${t.javaClass.simpleName}: ${t.message}")
            updateNotification("Snapshot failed: ${t.message}", complete = true)
        } finally {
            Crypto.wipe(plaintext)
        }
    }

    /** Stable byte string binding a content-stream `.usbs` file to its
     *  parent `.usbe` envelope. Format:
     *    "device-snapshot.v1 <appId> <schemaVersion> <createdAtMs> <label>"
     *  All fields are required to match between envelope and stream;
     *  any mismatch fails GCM verification on every chunk in the
     *  stream because chunkAad mixes externalAad in. */
    private fun streamAad(header: BackupEnvelope.Header): ByteArray =
        ("device-snapshot.v1 ${header.appId} ${header.schemaVersion}" +
            " ${header.createdAtMs} ${header.label}")
            .toByteArray(Charsets.UTF_8)

    private fun writeEnvelope(
        destinationTreeUri: String?,
        ts: String,
        header: BackupEnvelope.Header,
        plaintext: ByteArray,
        key: AesGcmPassphraseCodec.PassphraseKey,
    ) {
        val filename = "device-$ts.usbe"
        openOutput(destinationTreeUri, filename).use { out ->
            BackupEnvelope.write(
                out = out,
                codec = AesGcmPassphraseCodec,
                header = header,
                plaintext = plaintext,
                codecKey = key,
            )
        }
        Diagnostics.log("backups.DeviceSnapshotService", "wrote $filename")
    }

    /** Stream-encrypt the user-dir content into a sibling `.usbs` file.
     *
     *  Memory: bounded by [StreamingAesGcmCodec.DEFAULT_CHUNK_SIZE]
     *  (1 MiB). Total snapshot size is bounded only by the destination's
     *  free space — internal storage hits the OS app-quota first, SAF
     *  tree URIs typically have the device's external-storage limit.
     *
     *  The same [passphrase] is used as the envelope's; the streaming
     *  codec independently derives its KEK via Argon2id on a fresh
     *  random salt. Two derivation paths share the secret but not the
     *  derived keys, which is what we want — the .usbs file is
     *  decryptable only by someone who knows the master passphrase,
     *  and successful decryption proves the file matches the
     *  envelope's identity (via the streamAad).
     */
    private fun writeContentStream(
        destinationTreeUri: String?,
        ts: String,
        header: BackupEnvelope.Header,
        passphrase: CharArray,
    ) {
        val filename = "device-$ts.usbs"
        val aad = streamAad(header)
        UserDirsContentStream.open().use { input ->
            openOutput(destinationTreeUri, filename).use { out ->
                StreamingAesGcmCodec.encrypt(
                    plaintext = input,
                    ciphertext = out,
                    passphrase = passphrase.copyOf(),
                    externalAad = aad,
                )
            }
        }
        Diagnostics.log("backups.DeviceSnapshotService", "wrote $filename")
    }

    /** Single helper that abstracts internal-vs-SAF output. Returns an
     *  OutputStream the caller is responsible for closing (use `.use`). */
    private fun openOutput(destinationTreeUri: String?, filename: String): OutputStream {
        if (destinationTreeUri == null) {
            // Internal storage. Reuse the LocalSnapshotStore's directory.
            val outFile = File(LocalSnapshotStore.snapshotDir(this), filename)
            return FileOutputStream(outFile)
        }
        val tree = Uri.parse(destinationTreeUri)
        val docTree = androidx.documentfile.provider.DocumentFile.fromTreeUri(this, tree)
            ?: throw IllegalStateException("destinationTreeUri not resolvable")
        val doc = docTree.createFile("application/octet-stream", filename)
            ?: throw IllegalStateException("createFile returned null under $tree")
        return contentResolver.openOutputStream(doc.uri, "w")
            ?: throw IllegalStateException("couldn't open SAF output stream for $filename")
    }

    private fun updateNotification(text: String, complete: Boolean = false) {
        val notif = buildNotification(text, complete = complete)
        runCatching {
            getSystemService(NotificationManager::class.java)
                ?.notify(NOTIF_ID, notif)
        }
    }

    private fun buildNotification(
        text: String,
        progress: Int? = null,
        complete: Boolean = false,
    ): Notification {
        ensureChannel()
        val pendingMain = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(if (complete) "Snapshot complete" else "Snapshotting device")
            .setContentText(text)
            .setOngoing(!complete)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingMain)
        if (progress != null && !complete) builder.setProgress(100, progress, false)
        return builder.build()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "Device snapshot",
                    NotificationManager.IMPORTANCE_LOW,
                ).apply { description = "Progress + completion of device-wide snapshots." }
            )
        }
    }

    companion object {
        const val CHANNEL_ID = "device_snapshot"
        const val NOTIF_ID = 3
        const val ACTION_STOP = "com.understory.backups.devicesnapshot.ACTION_STOP"
        const val EXTRA_PASSPHRASE = "passphrase"

        fun start(ctx: Context, passphrase: CharArray) {
            ctx.startForegroundService(
                Intent(ctx, DeviceSnapshotService::class.java).apply {
                    putExtra(EXTRA_PASSPHRASE, passphrase)
                }
            )
        }

        fun stop(ctx: Context) {
            ctx.startForegroundService(
                Intent(ctx, DeviceSnapshotService::class.java).apply {
                    action = ACTION_STOP
                }
            )
        }
    }
}
