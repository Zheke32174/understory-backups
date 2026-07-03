package com.understory.backups

import android.content.Context
import com.understory.backup.BackupEnvelope
import java.io.File
import java.io.FileInputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * On-device snapshot store for the backups app.
 *
 * Today the encrypt flow always asks SAF for an output URI, which means
 * every backup requires an explicit "save to where?" step. For users
 * who want a one-tap recurring local snapshot — keep encrypted backups
 * on the same phone, no cloud, no SAF round-trip — this object is the
 * destination side: a private app-internal directory under
 * [Context.getFilesDir]/snapshots/ that holds [BackupEnvelope]-formatted
 * files keyed by `<appLabel>-<timestamp>.usbe`.
 *
 * Design choices:
 * - **filesDir, not externalFilesDir**: the snapshot is encrypted but
 *   the metadata (which app, which timestamp) leaks via the filename.
 *   filesDir is private to the app's UID so peers can't enumerate.
 *   externalFilesDir would be world-readable on shared storage.
 * - **Filename only carries app label + ISO timestamp**: not the user
 *   label. The user label lives inside the envelope header, which we
 *   parse on demand for the list view.
 * - **No directory listing index file**: we walk the directory each
 *   time a screen wants the list. Snapshots are O(<100) per device for
 *   the foreseeable future; an index would be premature complexity.
 * - **Rotation is opt-in**: [rotate] is called explicitly by callers
 *   that want a "keep last N" policy. The store doesn't auto-prune.
 *
 * Cross-app dispatch (each app's BackupAdapter being callable from
 * here) is a separate piece of work; today the flow still feeds a
 * single-file SAF input through encryptToLocalSnapshot. When the
 * cross-app provider lands, [save] is the surface to call from a
 * walker that aggregates every app.
 */
object LocalSnapshotStore {

    /** Directory holding all locally-saved snapshots for this app. */
    fun snapshotDir(ctx: Context): File {
        val dir = File(ctx.filesDir, "snapshots")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    /**
     * Per-snapshot metadata exposed to UI. Header fields are parsed on
     * demand from the envelope; nothing here decrypts or unwraps the
     * payload.
     */
    data class Info(
        val file: File,
        val appLabel: String,
        val userLabel: String,
        val createdAtMs: Long,
        val sizeBytes: Long,
    ) {
        /** Display-friendly timestamp, locale-default. */
        fun formattedTimestamp(): String =
            SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
                .format(Date(createdAtMs))
    }

    /**
     * Reserve a new snapshot file path. Filename pattern is
     * `<appLabel>-<UTC-ISO>.usbe`, with `appLabel` lowercased and
     * non-alnum stripped so the filename stays predictable across apps.
     * The file is NOT created here — caller passes it to
     * [BackupEnvelope.write] which creates and fills it.
     */
    fun reserveNew(ctx: Context, appLabel: String): File {
        val sanitized = appLabel.lowercase()
            .filter { it.isLetterOrDigit() || it == '-' || it == '_' }
            .ifEmpty { "backup" }
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }
            .format(Date())
        return File(snapshotDir(ctx), "$sanitized-$ts.usbe")
    }

    /**
     * List every snapshot in the directory, newest first. Each entry's
     * envelope header is parsed to surface the app label, user label,
     * and creation timestamp; failures (corrupted file, partial write
     * from a crashed encrypt) are skipped silently in this MVP — the
     * file is left in place so the user can inspect it via diagnostics
     * if needed.
     */
    fun list(ctx: Context): List<Info> {
        val dir = snapshotDir(ctx)
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".usbe") }
            ?: return emptyList()
        return files.mapNotNull { f ->
            runCatching {
                FileInputStream(f).use { stream ->
                    val parsed = BackupEnvelope.parse(stream)
                    Info(
                        file = f,
                        appLabel = parsed.header.appId,
                        userLabel = parsed.header.label,
                        createdAtMs = parsed.header.createdAtMs,
                        sizeBytes = f.length(),
                    )
                }
            }.getOrNull()
        }.sortedByDescending { it.createdAtMs }
    }

    /** Delete one snapshot. Returns true on success. */
    fun delete(file: File): Boolean = runCatching { file.delete() }.getOrDefault(false)

    /**
     * Keep the most-recent [keepLast] snapshots; delete the rest.
     * No-op when there are fewer snapshots than the keep count.
     */
    fun rotate(ctx: Context, keepLast: Int) {
        require(keepLast >= 0) { "keepLast must be non-negative" }
        val all = list(ctx)
        if (all.size <= keepLast) return
        all.drop(keepLast).forEach { delete(it.file) }
    }

    // --- Retention setting (D-15 / A-10): the "Keep last N" policy the UI
    //     exposes and the write paths apply. 0 = Off (keep everything). ---

    private const val PREF = "local_snapshot_store"
    private const val K_KEEP_LAST = "retention_keep_last"

    /** Allowed retention choices surfaced in the Local snapshots screen. */
    val RETENTION_CHOICES = listOf(0, 5, 10, 20)

    /** Current "keep last N" setting; 0 means Off (unbounded). */
    fun retentionKeepLast(ctx: Context): Int =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).getInt(K_KEEP_LAST, 0)

    fun setRetentionKeepLast(ctx: Context, keepLast: Int) {
        require(keepLast >= 0) { "keepLast must be non-negative" }
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .edit().putInt(K_KEEP_LAST, keepLast).apply()
    }

    /**
     * Apply the persisted retention policy after a successful local write.
     * No-op when retention is Off (0). Called by every path that writes a new
     * local snapshot so "keep last N" is honored uniformly (D-15).
     */
    fun applyRetention(ctx: Context) {
        val keep = retentionKeepLast(ctx)
        if (keep > 0) rotate(ctx, keep)
    }
}
