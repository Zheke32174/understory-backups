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
 * into [com.understory.backup.StreamingAesGcmCodec]. The reverse
 * (decrypt + write files back) is [UserDirsContentRestore].
 *
 * Wire format inside the streaming-encrypted blob — **UDCSv002**, a
 * self-delimiting block framing that does NOT depend on a length promised
 * before the bytes are read (backups.md §2.4, fixes D-3):
 *
 *   header:
 *     +-------+--------+--------------------------------------+
 *     |  off  | size   | field                                |
 *     +-------+--------+--------------------------------------+
 *     |   0   | 8      | magic = "UDCSv002" (ASCII)           |
 *     +-------+--------+--------------------------------------+
 *
 *   then a sequence of file entries until end-of-stream, each:
 *     +-------+--------+--------------------------------------+
 *     |   0   | 4 BE   | path_len (must fit in [MAX_PATH_BYTES])|
 *     |   4   | path_l | UTF-8 relative path, section-prefixed |
 *     | 4+pl  | 1      | entry_start marker 0x01 (resync)      |
 *     |       |        | then body blocks, each:               |
 *     |       | 4 BE   |   block_len (0x00000000 = end-of-entry)|
 *     |       | block_l|   block_len bytes of file data        |
 *     |       | 8 BE   | actual_bytes_written (BE) trailer     |
 *     +-------+--------+--------------------------------------+
 *
 * Why UDCSv002 over the old length-prefixed UDCSv001:
 *   The v001 writer emitted a `content_length` from `file.length()` at
 *   walk time, then lazily streamed the file. If the file grew/shrank/
 *   vanished between walk and stream, the byte count no longer matched
 *   the promised length and every subsequent frame boundary slid, silently
 *   corrupting the whole rest of the archive with no way to detect it. The
 *   v002 writer streams the file in <=1 MiB blocks emitting each block's
 *   REAL length as it reads, terminates with a 0-length sentinel, and
 *   writes the true total in a trailer — so there is no pre-committed
 *   length that can be wrong. A file that shrank simply ends early and
 *   cleanly; a file that grew is fully captured. The [ENTRY_START] resync
 *   marker lets the unpacker assert structural integrity before each path
 *   and abort with a precise offset rather than half-parse.
 *
 * The whole UDCS payload is wrapped by [com.understory.backup.StreamingAesGcmCodec],
 * so every block length is itself GCM-authenticated — an attacker cannot
 * forge a resync marker or block length without the key.
 *
 * Memory: the implementation reads files lazily via [SequenceInputStream]
 * + per-entry lazy block streams. Memory cost is bounded by the streaming
 * codec's chunk size + [BLOCK_SIZE], NOT by total snapshot size.
 *
 * Skipped files: anything unreadable is skipped silently — the snapshot
 * is best-effort by design. The companion manifest collector records file
 * metadata authoritatively so the restore tool can reconcile gaps.
 */
object UserDirsContentStream {

    val MAGIC: ByteArray = "UDCSv002".toByteArray(Charsets.US_ASCII)
    const val MAX_PATH_BYTES = 16 * 1024
    const val ENTRY_START: Byte = 0x01

    /** Body-block size the writer emits per read (backups.md §2.4: <=1 MiB). */
    const val BLOCK_SIZE = 1 shl 20

    /**
     * Upper bound the unpacker enforces on any single block_len, so a
     * corrupt/hostile (but somehow authenticated) length can't drive an
     * absurd allocation. Matches [BLOCK_SIZE]; the writer never exceeds it.
     */
    const val MAX_BLOCK_BYTES = BLOCK_SIZE

    /** Same dirs as [UserDirsManifestCollector]. */
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
     * user dirs in UDCSv002 self-delimiting form.
     *
     * Caller is responsible for closing the returned stream (which
     * closes the per-entry streams as it advances).
     */
    fun open(): InputStream {
        val streams = mutableListOf<InputStream>(
            java.io.ByteArrayInputStream(MAGIC),
        )
        var fileCount = 0
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
                        val sectionRel = "$label/$rel"
                        val pathBytes = sectionRel.toByteArray(Charsets.UTF_8)
                        if (pathBytes.size > MAX_PATH_BYTES) {
                            Diagnostics.log("backups.UserDirsContent",
                                "skip oversized path: ${pathBytes.size} bytes")
                            return@forEach
                        }
                        // Entry preamble: 4B path_len + path + 0x01 marker.
                        streams.add(
                            java.io.ByteArrayInputStream(buildEntryPreamble(pathBytes)),
                        )
                        // Body: self-delimiting blocks + 0-sentinel + trailer,
                        // produced lazily so at most one file is open at a time.
                        streams.add(BlockFramedFileStream(file))
                        fileCount++
                    }
            } catch (t: Throwable) {
                Diagnostics.error("backups.UserDirsContent",
                    "walking $label threw: ${t.javaClass.simpleName}: ${t.message}")
                continue
            }
        }
        Diagnostics.log("backups.UserDirsContent", "stream prepared: files=$fileCount")
        return SequenceInputStream(Collections.enumeration(streams))
    }

    /** 4-byte BE path length + path bytes + 1-byte [ENTRY_START] marker. */
    private fun buildEntryPreamble(pathBytes: ByteArray): ByteArray {
        val out = ByteArray(4 + pathBytes.size + 1)
        out[0] = ((pathBytes.size ushr 24) and 0xFF).toByte()
        out[1] = ((pathBytes.size ushr 16) and 0xFF).toByte()
        out[2] = ((pathBytes.size ushr 8) and 0xFF).toByte()
        out[3] = (pathBytes.size and 0xFF).toByte()
        System.arraycopy(pathBytes, 0, out, 4, pathBytes.size)
        out[4 + pathBytes.size] = ENTRY_START
        return out
    }

    /**
     * Emits a single file's body in UDCSv002 block framing:
     *   { 4B block_len, block_len bytes } * ...
     *   4B 0x00000000  (end-of-entry sentinel)
     *   8B total_bytes_written (BE)
     *
     * The whole framing is generated on the fly from lazy reads of [file], so
     * memory is bounded by [BLOCK_SIZE] and the file is opened only when this
     * stream is first read (fd-limit safety across a 10k-file walk). If the
     * file disappears or errors mid-read, the entry ends cleanly at the next
     * sentinel with whatever bytes were captured — the trailer records the
     * true total, which is authoritative on restore.
     */
    private class BlockFramedFileStream(private val file: File) : InputStream() {
        private var delegate: InputStream? = null
        private var opened = false
        private var eofOfFile = false

        // Pending framed bytes not yet consumed by the caller.
        private var pending: ByteArray = ByteArray(0)
        private var pendingPos = 0

        private var totalWritten = 0L
        private var trailerEmitted = false
        private val readBuf = ByteArray(BLOCK_SIZE)

        private fun ensureOpen() {
            if (opened) return
            opened = true
            delegate = try {
                file.inputStream()
            } catch (t: Throwable) {
                Diagnostics.log("backups.UserDirsContent",
                    "open failed for ${file.name}: ${t.javaClass.simpleName}")
                eofOfFile = true
                null
            }
        }

        /** Refill [pending] with the next framed unit, or leave it empty when
         *  the entire entry (blocks + sentinel + trailer) has been emitted. */
        private fun refill(): Boolean {
            if (pendingPos < pending.size) return true
            ensureOpen()
            if (!eofOfFile) {
                val n = try {
                    delegate?.read(readBuf, 0, BLOCK_SIZE) ?: -1
                } catch (t: Throwable) {
                    Diagnostics.log("backups.UserDirsContent",
                        "read failed for ${file.name}: ${t.javaClass.simpleName}")
                    -1
                }
                if (n > 0) {
                    // Frame: 4B block_len + n bytes.
                    val framed = ByteArray(4 + n)
                    framed[0] = ((n ushr 24) and 0xFF).toByte()
                    framed[1] = ((n ushr 16) and 0xFF).toByte()
                    framed[2] = ((n ushr 8) and 0xFF).toByte()
                    framed[3] = (n and 0xFF).toByte()
                    System.arraycopy(readBuf, 0, framed, 4, n)
                    totalWritten += n
                    pending = framed
                    pendingPos = 0
                    return true
                }
                // n <= 0 : end of file. Fall through to sentinel + trailer.
                eofOfFile = true
                runCatching { delegate?.close() }
            }
            if (!trailerEmitted) {
                trailerEmitted = true
                // 4B zero sentinel + 8B BE total.
                val tail = ByteArray(4 + 8)
                // sentinel already zero
                var t = totalWritten
                for (i in 11 downTo 4) {
                    tail[i] = (t and 0xFF).toByte()
                    t = t ushr 8
                }
                pending = tail
                pendingPos = 0
                return true
            }
            return false
        }

        override fun read(): Int {
            if (!refill()) return -1
            return pending[pendingPos++].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (!refill()) return -1
            val avail = pending.size - pendingPos
            val k = minOf(avail, len)
            System.arraycopy(pending, pendingPos, b, off, k)
            pendingPos += k
            return k
        }

        override fun close() {
            runCatching { delegate?.close() }
        }
    }
}
