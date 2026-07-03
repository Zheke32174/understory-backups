package com.understory.backups

import android.os.Environment
import com.understory.security.Diagnostics
import java.io.File
import java.io.InputStream
import java.io.SequenceInputStream
import java.util.Collections

/**
 * Streams the full contents of the standard Android user-content
 * directories as a single packed [InputStream], suitable for feeding
 * into [com.understory.backup.StreamingAesGcmCodec].
 *
 * Wire format inside the streaming-encrypted blob:
 *
 *   header:
 *     +-------+--------+--------------------------------------+
 *     |  off  | size   | field                                |
 *     +-------+--------+--------------------------------------+
 *     |   0   | 8      | magic = "UDCSv001" (ASCII)           |
 *     +-------+--------+--------------------------------------+
 *
 *   then a sequence of file entries until end-of-stream:
 *     +-------+--------+--------------------------------------+
 *     |   0   | 4 BE   | path_length (must fit in 16 KiB)     |
 *     |   4   | path_l | UTF-8 relative path, NFC normalized  |
 *     |  4+pl | 8 BE   | content_length (signed, max 2^62)    |
 *     |       | cl     | file bytes                           |
 *     +-------+--------+--------------------------------------+
 *
 * Why no per-entry sentinel: the streaming codec already carries an
 * end-of-stream signal (final-flag in the chunk's AAD). When the
 * decoder runs out of bytes mid-entry it knows it's truncated; when
 * it cleanly exhausts the stream after a complete entry it knows it's
 * done. No additional EOF marker required.
 *
 * Why 16 KiB path cap: real-world Android paths are well under 4 KiB
 * (PATH_MAX is typically 4096). 16 KiB is a generous bound that
 * defends against malformed file walks producing absurd paths,
 * without imposing an arbitrarily tight limit.
 *
 * Why 2^62 content cap: practical filesystem max-file-size on
 * Android (ext4 / f2fs) is well under this; the cap exists so an
 * out-of-band tampered length field can't trick the decoder into
 * negative-length reads.
 *
 * Memory: the implementation reads files lazily via [SequenceInputStream]
 * + per-file lazy [java.io.FileInputStream]s. Memory cost is bounded
 * by the streaming codec's chunk size, NOT by total snapshot size.
 *
 * Skipped files: anything we can't read (permission_denied, broken
 * symlink, transient I/O error) is skipped silently — the snapshot
 * is best-effort by design. The companion manifest collector
 * (UserDirsManifestCollector) records file metadata authoritatively
 * so the restore tool can reconcile manifest-vs-content gaps.
 */
object UserDirsContentStream {

    val MAGIC: ByteArray = "UDCSv001".toByteArray(Charsets.US_ASCII)
    const val MAX_PATH_BYTES = 16 * 1024
    const val MAX_CONTENT_BYTES = (1L shl 62) - 1

    /** Same dirs as [UserDirsManifestCollector]. Keeping them in sync
     *  is a manual invariant for now; both collectors operate on the
     *  same logical scope. If divergence becomes useful (e.g.,
     *  manifest-everything but content-only-photos), introduce a
     *  shared SnapshotDirSet enum. */
    private val STANDARD_DIRS = listOf(
        "Pictures" to Environment.DIRECTORY_PICTURES,
        "DCIM" to Environment.DIRECTORY_DCIM,
        "Downloads" to Environment.DIRECTORY_DOWNLOADS,
        "Documents" to Environment.DIRECTORY_DOCUMENTS,
        "Music" to Environment.DIRECTORY_MUSIC,
        "Movies" to Environment.DIRECTORY_MOVIES,
    )

    /**
     * Build a single [InputStream] that, when fully read, yields the
     * 8-byte magic followed by every readable file from the standard
     * user dirs in path-prefixed framed form.
     *
     * Caller is responsible for closing the returned stream (which
     * closes the per-file streams as it advances). Typical use:
     *
     *     UserDirsContentStream.open().use { input ->
     *         StreamingAesGcmCodec.encrypt(
     *             plaintext = input,
     *             ciphertext = safOutputStream,
     *             passphrase = passphraseChars,
     *             externalAad = envelopeHeaderBytes,
     *         )
     *     }
     */
    fun open(): InputStream {
        val streams = mutableListOf<InputStream>(
            // Magic first, so a partial read can't be confused with
            // a file path-length prefix.
            java.io.ByteArrayInputStream(MAGIC),
        )
        var fileCount = 0
        var totalBytes = 0L
        for ((label, envKey) in STANDARD_DIRS) {
            val root = Environment.getExternalStoragePublicDirectory(envKey)
            if (!root.exists() || !root.canRead()) {
                Diagnostics.log("backups.UserDirsContent",
                    "skipping $label: missing or unreadable")
                continue
            }
            try {
                root.walkTopDown()
                    .filter { it.isFile && it.canRead() }
                    .forEach { file ->
                        val rel = file.absolutePath
                            .removePrefix(root.absolutePath)
                            .trimStart('/')
                        // Prefix the path with the section label so
                        // the restore tool can route entries back to
                        // the right dir even if Pictures and Music
                        // happened to share a relative subpath.
                        val sectionRel = "$label/$rel"
                        val pathBytes = sectionRel.toByteArray(Charsets.UTF_8)
                        if (pathBytes.size > MAX_PATH_BYTES) {
                            Diagnostics.log("backups.UserDirsContent",
                                "skip oversized path: ${pathBytes.size} bytes")
                            return@forEach
                        }
                        val len = file.length()
                        if (len < 0 || len > MAX_CONTENT_BYTES) {
                            Diagnostics.log("backups.UserDirsContent",
                                "skip malformed length $len for $sectionRel")
                            return@forEach
                        }
                        streams.add(java.io.ByteArrayInputStream(buildEntryHeader(pathBytes, len)))
                        // FileInputStream is opened lazily by
                        // SequenceInputStream when this entry's turn
                        // comes; not all at once. That's the memory
                        // bound: open one file at a time, not all of
                        // them up front.
                        streams.add(LazyFileInputStream(file))
                        fileCount++
                        totalBytes += len
                    }
            } catch (t: Throwable) {
                Diagnostics.error("backups.UserDirsContent",
                    "walking $label threw: ${t.javaClass.simpleName}: ${t.message}")
                continue
            }
        }
        Diagnostics.log("backups.UserDirsContent",
            "stream prepared: files=$fileCount bytes=$totalBytes")
        return SequenceInputStream(Collections.enumeration(streams))
    }

    private fun buildEntryHeader(pathBytes: ByteArray, contentLen: Long): ByteArray {
        val out = ByteArray(4 + pathBytes.size + 8)
        // 4-byte BE path length
        out[0] = ((pathBytes.size ushr 24) and 0xFF).toByte()
        out[1] = ((pathBytes.size ushr 16) and 0xFF).toByte()
        out[2] = ((pathBytes.size ushr 8) and 0xFF).toByte()
        out[3] = (pathBytes.size and 0xFF).toByte()
        System.arraycopy(pathBytes, 0, out, 4, pathBytes.size)
        // 8-byte BE content length
        val off = 4 + pathBytes.size
        out[off + 0] = ((contentLen ushr 56) and 0xFF).toByte()
        out[off + 1] = ((contentLen ushr 48) and 0xFF).toByte()
        out[off + 2] = ((contentLen ushr 40) and 0xFF).toByte()
        out[off + 3] = ((contentLen ushr 32) and 0xFF).toByte()
        out[off + 4] = ((contentLen ushr 24) and 0xFF).toByte()
        out[off + 5] = ((contentLen ushr 16) and 0xFF).toByte()
        out[off + 6] = ((contentLen ushr 8) and 0xFF).toByte()
        out[off + 7] = (contentLen and 0xFF).toByte()
        return out
    }

    /**
     * Defers opening the [File] until the first read, so we don't
     * blow through the per-process file-descriptor limit when the
     * walker enumerates 10k+ files. SequenceInputStream advances
     * sequentially so at most one [LazyFileInputStream] is "live"
     * (open) at any moment.
     *
     * If the file disappears or becomes unreadable between the
     * walker visit and the lazy open, [read] returns -1 immediately
     * (treated as zero-byte content). The content_length in the
     * preceding header was based on the file's size at walk time;
     * if the file shrank, the streaming codec will end up with
     * fewer bytes than the header claimed. The decoder must
     * tolerate this — a snapshot taken on a live filesystem is
     * inherently a slightly fuzzy point-in-time.
     */
    private class LazyFileInputStream(private val file: File) : InputStream() {
        private var delegate: InputStream? = null
        private var opened = false
        private var failed = false

        private fun ensureOpen(): InputStream? {
            if (failed) return null
            if (opened) return delegate
            opened = true
            delegate = try {
                file.inputStream()
            } catch (t: Throwable) {
                Diagnostics.log("backups.UserDirsContent",
                    "lazy-open failed for ${file.name}: ${t.javaClass.simpleName}")
                failed = true
                null
            }
            return delegate
        }

        override fun read(): Int = ensureOpen()?.read() ?: -1

        override fun read(b: ByteArray, off: Int, len: Int): Int =
            ensureOpen()?.read(b, off, len) ?: -1

        override fun close() {
            try {
                delegate?.close()
            } catch (_: Throwable) {
                // best-effort; the snapshot run owns the failure log
            }
        }
    }
}
