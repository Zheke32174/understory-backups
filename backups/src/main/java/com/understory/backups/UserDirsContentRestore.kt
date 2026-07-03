package com.understory.backups

import androidx.documentfile.provider.DocumentFile
import com.understory.security.Diagnostics
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * The reverse of [UserDirsContentStream]: consumes the DECRYPTED UDCSv002 byte
 * stream (already GCM-verified chunk-by-chunk by
 * [com.understory.backup.StreamingAesGcmCodec.decrypt]) and writes each entry
 * back as a file under a destination SAF tree (backups.md §2.3 — the D-2
 * restore tool). The codec verifies every chunk's tag and the final-flag before
 * the unpacker ever sees a byte, so a truncated/tampered stream aborts before
 * an affected file is emitted.
 *
 * Wire format is [UserDirsContentStream]'s UDCSv002 (self-delimiting blocks):
 *
 *   8B  magic "UDCSv002"
 *   per entry:
 *     4B  path_len (BE, <= [UserDirsContentStream.MAX_PATH_BYTES])
 *     N   path bytes (UTF-8, section-prefixed, e.g. "Pictures/holiday/x.jpg")
 *     1B  [UserDirsContentStream.ENTRY_START] resync marker (0x01)
 *     body blocks, each: 4B block_len (BE; 0 = end-of-entry) + block_len bytes
 *     8B  actual_bytes_written (BE) trailer
 *
 * Path-traversal guard: the writer never emits `..` or absolute segments, but
 * the reader MUST NOT trust that — any path with a `..` component, a leading
 * slash/backslash, a Windows drive letter, or an empty segment is rejected and
 * that entry is skipped (its body bytes are still consumed so the stream stays
 * framed and later entries survive).
 *
 * Output opening is passed in as [openStream] so the core parser is testable
 * without a live ContentResolver; the Restore screen supplies a resolver-backed
 * lambda over [DocumentFile]s created under the destination tree.
 */
object UserDirsContentRestore {

    /** One file's restore outcome, accumulated into the report. */
    data class EntryResult(
        val path: String,
        val bytesWritten: Long,
        val status: Status,
        val detail: String? = null,
    ) {
        enum class Status { WRITTEN, SKIPPED_UNSAFE_PATH, SKIPPED_WRITE_ERROR }
    }

    data class Report(val entries: List<EntryResult>) {
        val written: Int get() = entries.count { it.status == EntryResult.Status.WRITTEN }
        val skipped: Int get() = entries.size - written
        val totalBytes: Long get() = entries.sumOf { it.bytesWritten }
    }

    /**
     * Unpack [plaintext] (the decrypted UDCS stream) into [destTree], recreating
     * the `Section/rel/path` subtree via [DocumentFile.createDirectory]. Reads
     * until clean end-of-stream. Aborts with [IOException] on a structural
     * corruption (bad magic, missing resync marker, oversized length) so a
     * corrupt archive is reported precisely, not half-parsed.
     *
     * [plaintext] is NOT closed here — the caller owns its lifecycle (typically
     * the [java.io.PipedInputStream] read side). Each per-file [OutputStream]
     * returned by [openStream] is flushed + closed by this method.
     */
    fun unpack(
        plaintext: InputStream,
        destTree: DocumentFile,
        openStream: (DocumentFile) -> OutputStream,
    ): Report {
        val magic = ByteArray(8)
        if (readFully(plaintext, magic) != 8 ||
            !magic.contentEquals(UserDirsContentStream.MAGIC)
        ) {
            throw IOException("not a UDCSv002 stream (bad magic)")
        }
        val results = mutableListOf<EntryResult>()
        val dirCache = HashMap<String, DocumentFile>()
        var offset = 8L
        while (true) {
            // Peek the first byte of the next path_len; -1 = clean EOF.
            val first = plaintext.read()
            if (first < 0) break
            offset += 1
            val pathLen = readIntBEFirst(plaintext, first); offset += 3
            if (pathLen <= 0 || pathLen > UserDirsContentStream.MAX_PATH_BYTES) {
                throw IOException("bad path_len $pathLen at offset ${offset - 4}")
            }
            val pathBytes = ByteArray(pathLen)
            if (readFully(plaintext, pathBytes) != pathLen) {
                throw EOFException("truncated path at offset $offset")
            }
            offset += pathLen
            val marker = plaintext.read(); offset += 1
            if (marker != UserDirsContentStream.ENTRY_START.toInt()) {
                throw IOException(
                    "missing entry_start marker (got $marker) at offset ${offset - 1}; " +
                        "archive is structurally corrupt"
                )
            }
            val relPath = String(pathBytes, Charsets.UTF_8)
            val safe = isSafeRelativePath(relPath)
            val target = if (safe)
                runCatching { resolveTarget(destTree, relPath, dirCache) }.getOrNull()
            else null
            val out = if (safe && target != null)
                runCatching { openStream(target) }.getOrNull()
            else null

            var written = 0L
            var writeError = false
            // Read body blocks until the 0-length sentinel.
            while (true) {
                val blockLen = readIntBE(plaintext); offset += 4
                if (blockLen == 0) break
                if (blockLen < 0 || blockLen > UserDirsContentStream.MAX_BLOCK_BYTES) {
                    throw IOException("bad block_len $blockLen at offset ${offset - 4}")
                }
                val block = ByteArray(blockLen)
                if (readFully(plaintext, block) != blockLen) {
                    throw EOFException("truncated block at offset $offset")
                }
                offset += blockLen
                if (out != null && !writeError) {
                    try {
                        out.write(block); written += blockLen
                    } catch (t: Throwable) {
                        writeError = true
                        Diagnostics.log("backups.UserDirsRestore",
                            "write error for $relPath: ${t.javaClass.simpleName}")
                    }
                }
            }
            // 8-byte trailer: authoritative total; cross-check against written.
            val trailer = ByteArray(8)
            if (readFully(plaintext, trailer) != 8) {
                throw EOFException("truncated trailer at offset $offset")
            }
            offset += 8
            val declaredTotal = longBE(trailer)
            runCatching { out?.flush(); out?.close() }

            val status = when {
                !safe -> EntryResult.Status.SKIPPED_UNSAFE_PATH
                out == null || writeError -> EntryResult.Status.SKIPPED_WRITE_ERROR
                else -> EntryResult.Status.WRITTEN
            }
            val detail = when (status) {
                EntryResult.Status.SKIPPED_UNSAFE_PATH -> "path rejected (traversal guard)"
                EntryResult.Status.SKIPPED_WRITE_ERROR -> "could not write to destination"
                EntryResult.Status.WRITTEN ->
                    if (written != declaredTotal)
                        "wrote $written of a declared $declaredTotal bytes" else null
            }
            results += EntryResult(relPath, written, status, detail)
        }
        Diagnostics.log("backups.UserDirsRestore", "unpack done: ${results.size} entries")
        return Report(results)
    }

    /**
     * Reject any path that could escape [destTree]: `..` component, leading
     * slash/backslash, a Windows drive letter, or an empty segment. Accepts a
     * normal `Section/rel/path`.
     */
    fun isSafeRelativePath(path: String): Boolean {
        if (path.isBlank()) return false
        if (path.startsWith('/') || path.startsWith('\\')) return false
        if (path.contains('\\')) return false
        if (path.length >= 2 && path[1] == ':') return false // drive letter
        val segments = path.split('/')
        if (segments.isEmpty()) return false
        for (seg in segments) {
            if (seg.isEmpty()) return false
            if (seg == "." || seg == "..") return false
        }
        return true
    }

    /**
     * Resolve (creating intermediate directories) the [DocumentFile] to write
     * [relPath] into under [destTree]. The last segment is the filename; all
     * prior segments are directories. Reuses [dirCache] so a directory is
     * created once per restore. Overwrites a pre-existing same-named file.
     */
    private fun resolveTarget(
        destTree: DocumentFile,
        relPath: String,
        dirCache: HashMap<String, DocumentFile>,
    ): DocumentFile {
        val segments = relPath.split('/')
        val fileName = segments.last()
        var dir = destTree
        val sb = StringBuilder()
        for (i in 0 until segments.size - 1) {
            val seg = segments[i]
            if (sb.isNotEmpty()) sb.append('/')
            sb.append(seg)
            val cacheKey = sb.toString()
            val cached = dirCache[cacheKey]
            dir = if (cached != null) {
                cached
            } else {
                val existing = dir.findFile(seg)?.takeIf { it.isDirectory }
                val made = existing ?: dir.createDirectory(seg)
                    ?: throw IOException("couldn't create directory $seg")
                dirCache[cacheKey] = made
                made
            }
        }
        dir.findFile(fileName)?.takeIf { it.isFile }?.let { runCatching { it.delete() } }
        return dir.createFile("application/octet-stream", fileName)
            ?: throw IOException("couldn't create file $fileName")
    }

    // ---------- io helpers ----------

    private fun readFully(input: InputStream, buf: ByteArray): Int {
        var read = 0
        while (read < buf.size) {
            val n = input.read(buf, read, buf.size - read)
            if (n < 0) break
            read += n
        }
        return read
    }

    private fun readIntBE(input: InputStream): Int {
        val b0 = input.read()
        if (b0 < 0) throw EOFException("truncated int")
        return readIntBEFirst(input, b0)
    }

    /** Read a 4-byte BE int whose first byte [b0] is already consumed. */
    private fun readIntBEFirst(input: InputStream, b0: Int): Int {
        val b1 = input.read(); val b2 = input.read(); val b3 = input.read()
        if ((b1 or b2 or b3) < 0) throw EOFException("truncated int")
        return (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
    }

    private fun longBE(b: ByteArray): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[i].toLong() and 0xFF)
        return v
    }
}
