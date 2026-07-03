package com.understory.backups

import android.content.Context
import android.os.Environment
import com.understory.security.Diagnostics
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Walks the standard Android user-content directories and emits a
 * MANIFEST: per-file `(relative_path, size_bytes, mtime_ms,
 * sha256_first_64KiB)` tuples. NOT file contents.
 *
 * Why a manifest, not the bytes (yet):
 *
 *   Full-content backup of GB-sized media collections needs streaming
 *   AES-GCM encryption (chunked, per-block tag) writing to either a
 *   SAF tree URI or a sized internal file. The buffer-based
 *   BackupEnvelope path used by single-file backups can't fit a 50 GB
 *   Pictures dir in memory. That's Wave B-2.
 *
 *   In the meantime: the manifest answers "what files do I have?",
 *   gives a stable identity hash (sha256 of the first 64 KiB) so
 *   restores can deduplicate against existing files, and lets the
 *   user verify the snapshot inventory matches reality before
 *   committing to a full-content run.
 *
 * Permissions:
 *
 *   This collector reads files via java.io.File enumeration of the
 *   public external dirs (Environment.DIRECTORY_PICTURES etc. under
 *   /storage/emulated/0/). On API 33+ that requires READ_MEDIA_IMAGES
 *   / READ_MEDIA_VIDEO / READ_MEDIA_AUDIO; on older it requires
 *   READ_EXTERNAL_STORAGE. Caller is responsible for the runtime
 *   permission flow before invoking collect(). collect() returns an
 *   empty section for any dir we can't read instead of crashing.
 *
 * Output shape (JSON, one section per requested dir):
 *
 *   {
 *     "Pictures": {
 *       "root": "/storage/emulated/0/Pictures",
 *       "files": [
 *         {"path":"holiday/2024/IMG_0001.jpg","size":3214567,"mtime":...,"sha256_64k":"..."},
 *         ...
 *       ]
 *     },
 *     ...
 *   }
 */
object UserDirsManifestCollector {

    /** Standard public dirs we know how to enumerate. Each maps to an
     *  Environment.DIRECTORY_* constant for the absolute path. */
    private val STANDARD_DIRS = listOf(
        "Pictures" to Environment.DIRECTORY_PICTURES,
        "DCIM" to Environment.DIRECTORY_DCIM,
        "Downloads" to Environment.DIRECTORY_DOWNLOADS,
        "Documents" to Environment.DIRECTORY_DOCUMENTS,
        "Music" to Environment.DIRECTORY_MUSIC,
        "Movies" to Environment.DIRECTORY_MOVIES,
    )

    /** Per-file fingerprint window. SHA-256 of the first 64 KiB is a
     *  cheap collision-resistant identity for media files (the
     *  filesystem-typical block alignment means the first 64 KiB of
     *  two distinct images / videos almost always differ). 256 KiB
     *  would be ~certain but quadruple the IO. */
    private const val FINGERPRINT_BYTES = 64 * 1024

    /** Cap per-section file count to keep the manifest from blowing
     *  up on a 100k-file Pictures dir. Files past the cap are
     *  summarized in an "overflow" entry. */
    private const val MAX_FILES_PER_SECTION = 5_000

    fun collect(ctx: Context): String {
        val out = JSONObject()
        var totalFiles = 0
        var totalBytes = 0L
        for ((label, envKey) in STANDARD_DIRS) {
            val root = Environment.getExternalStoragePublicDirectory(envKey)
            val section = collectDir(label, root)
            out.put(label, section)
            totalFiles += section.optJSONArray("files")?.length() ?: 0
            totalBytes += section.optLong("total_bytes", 0L)
        }
        out.put("collected_at_ms", System.currentTimeMillis())
        out.put("total_files", totalFiles)
        out.put("total_bytes", totalBytes)
        Diagnostics.log("backups.UserDirsManifest",
            "collected: files=$totalFiles bytes=$totalBytes")
        return out.toString()
    }

    private fun collectDir(label: String, root: File): JSONObject {
        val section = JSONObject()
        section.put("root", root.absolutePath)
        if (!root.exists()) {
            section.put("status", "missing")
            return section
        }
        if (!root.canRead()) {
            section.put("status", "permission_denied")
            return section
        }

        val files = JSONArray()
        var totalBytes = 0L
        var skipped = 0
        var visited = 0
        try {
            root.walkTopDown()
                .filter { it.isFile && it.canRead() }
                .forEach { file ->
                    visited++
                    if (files.length() >= MAX_FILES_PER_SECTION) {
                        skipped++
                        return@forEach
                    }
                    val rel = file.absolutePath.removePrefix(root.absolutePath).trimStart('/')
                    val entry = JSONObject().apply {
                        put("path", rel)
                        put("size", file.length())
                        put("mtime", file.lastModified())
                        put("sha256_64k", fingerprint(file))
                    }
                    files.put(entry)
                    totalBytes += file.length()
                }
        } catch (t: Throwable) {
            Diagnostics.error("backups.UserDirsManifest",
                "walking $label threw: ${t.javaClass.simpleName}: ${t.message}")
            section.put("status", "walk_error")
            section.put("error", t.message ?: t.javaClass.simpleName)
            return section
        }
        section.put("status", "ok")
        section.put("files", files)
        section.put("total_bytes", totalBytes)
        section.put("visited", visited)
        section.put("skipped_due_to_cap", skipped)
        return section
    }

    /** SHA-256 hex of the first [FINGERPRINT_BYTES] of the file.
     *  Returns "(unreadable)" if the open / read fails so the manifest
     *  entry stays valid. */
    private fun fingerprint(f: File): String = runCatching {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        f.inputStream().use { input ->
            val buf = ByteArray(8 * 1024)
            var read = 0
            while (read < FINGERPRINT_BYTES) {
                val want = minOf(buf.size, FINGERPRINT_BYTES - read)
                val n = input.read(buf, 0, want)
                if (n < 0) break
                md.update(buf, 0, n)
                read += n
            }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    }.getOrDefault("(unreadable)")
}
