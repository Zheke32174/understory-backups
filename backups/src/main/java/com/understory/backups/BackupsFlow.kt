package com.understory.backups

import android.content.Context
import android.net.Uri
import com.understory.backup.AesGcmPassphraseCodec
import com.understory.backup.BackupEnvelope
import com.understory.backup.StreamingAesGcmCodec
import com.understory.security.Crypto
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * The actual envelope-encrypt and envelope-decrypt operations exposed
 * to MainActivity. Pure logic — no UI concerns. The MainActivity binds
 * these to the Compose flow with SAF picker results and a
 * passphrase-CharArray that it owns.
 *
 * Hygiene contract: the [passphrase] CharArray is OWNED by these calls
 * for the duration of the operation; both methods construct a
 * PassphraseKey, run, and call .wipe() before returning. Caller MUST
 * NOT continue to use the CharArray after the call returns — its bytes
 * are zero.
 *
 * MVP scope (this iteration): operates on raw bytes from any
 * SAF-picked file. The user is encrypting/decrypting *something* into
 * the BackupEnvelope format. Cross-app integration with passgen +
 * aegis BackupAdapters lands in a follow-up that wires Intent calls
 * to the peer apps; for now the orchestrator is a generic envelope
 * tool. Files written by this app can be decrypted by it, AND will be
 * decryptable by the eventual cross-app integration once the
 * BackupAdapter consumers come online.
 */
object BackupsFlow {

    /** 16 MiB cap on input size. Backups should be small; bigger inputs
     *  are almost certainly a mistake (user picked a video). Public so the
     *  Encrypt screen can pre-flight the picked URI's size (§11, D-18) and
     *  disable Encrypt with a reason instead of failing mid-stream. */
    const val MAX_INPUT_SIZE = 16 * 1024 * 1024

    sealed class Result {
        data class Success(val message: String) : Result()
        data class Failure(val message: String) : Result()
    }

    /**
     * The format a restore input is, sniffed from its leading magic bytes
     * (backups.md §2.1). One `restore` screen dispatches on this so the user
     * never has to know which format a file is.
     */
    enum class InputFormat {
        /** `USBE` — single-shot [BackupEnvelope]; plaintext is a user file. */
        ENVELOPE,

        /**
         * `USBE` whose header appId is the device-snapshot id — its plaintext
         * is a JSON device bundle, routed to the bundle report, not raw-out.
         */
        DEVICE_SNAPSHOT_ENVELOPE,

        /** `USTRSTRM` — streaming `.usbs` UDCS content stream. */
        CONTENT_STREAM,

        /** Leading bytes match no known format. */
        UNKNOWN,
    }

    /** appId that marks a device-snapshot envelope (see [DeviceSnapshotService]). */
    const val DEVICE_SNAPSHOT_APP_ID = "com.understory.backups.device-snapshot"

    /**
     * Peek the leading magic bytes of [uri] and classify the format
     * (backups.md §2.1). For an `USBE` envelope the header is parsed (cheap,
     * no decrypt) to route device-snapshot bundles separately. Never decrypts.
     * Returns [InputFormat.UNKNOWN] on any read/parse failure so the caller can
     * show an honest "unrecognized file" message rather than crashing.
     */
    fun sniff(ctx: Context, uri: Uri): InputFormat {
        return try {
            ctx.contentResolver.openInputStream(uri).use { raw ->
                requireNotNull(raw) { "couldn't open input stream" }
                val input = BufferedInputStream(raw)
                input.mark(8)
                val magic = ByteArray(8)
                val n = readFullyOrLess(input, magic)
                if (n < 4) return InputFormat.UNKNOWN
                when {
                    magic.copyOfRange(0, 4).contentEquals(BackupEnvelope.MAGIC) -> {
                        // Rewind and parse the (public) header to check appId.
                        input.reset()
                        val parsed = runCatching { BackupEnvelope.parse(input) }.getOrNull()
                        if (parsed != null &&
                            parsed.header.appId == DEVICE_SNAPSHOT_APP_ID
                        ) InputFormat.DEVICE_SNAPSHOT_ENVELOPE
                        else InputFormat.ENVELOPE
                    }
                    n >= 8 && magic.contentEquals(StreamingAesGcmCodec.MAGIC) ->
                        InputFormat.CONTENT_STREAM
                    else -> InputFormat.UNKNOWN
                }
            }
        } catch (_: Throwable) {
            InputFormat.UNKNOWN
        }
    }

    private fun readFullyOrLess(input: java.io.InputStream, buf: ByteArray): Int {
        var read = 0
        while (read < buf.size) {
            val k = input.read(buf, read, buf.size - read)
            if (k < 0) break
            read += k
        }
        return read
    }

    /**
     * Encrypt the bytes at [inputUri] with [passphrase] and write the
     * resulting envelope to [outputUri]. Both URIs come from SAF
     * pickers; we hold per-URI grants only for the duration of the
     * stream open/close.
     *
     * [appLabel] becomes the envelope's appId (informational).
     * [userLabel] becomes the human-readable label inside the header.
     */
    fun encryptToEnvelope(
        ctx: Context,
        inputUri: Uri,
        outputUri: Uri,
        appLabel: String,
        userLabel: String,
        passphrase: CharArray,
    ): Result {
        val plaintext: ByteArray = try {
            readBoundedBytes(ctx, inputUri)
        } catch (t: Throwable) {
            return Result.Failure("Couldn't read input: ${t.message ?: t.javaClass.simpleName}")
        }

        val key = AesGcmPassphraseCodec.PassphraseKey(passphrase)
        try {
            val header = BackupEnvelope.Header(
                appId = appLabel,
                schemaVersion = 1,
                createdAtMs = System.currentTimeMillis(),
                label = userLabel,
                codecParams = emptyMap(),
            )
            ctx.contentResolver.openOutputStream(outputUri, "w").use { out ->
                requireNotNull(out) { "couldn't open output stream" }
                BackupEnvelope.write(
                    out = out,
                    codec = AesGcmPassphraseCodec,
                    header = header,
                    plaintext = plaintext,
                    codecKey = key,
                )
            }
        } catch (t: Throwable) {
            Crypto.wipe(plaintext)
            return Result.Failure("Encrypt failed: ${t.message ?: t.javaClass.simpleName}")
        } finally {
            key.wipe()
        }
        Crypto.wipe(plaintext)
        return Result.Success("Encrypted ${plaintext.size} bytes → envelope at chosen location.")
    }

    /**
     * Decrypt [inputUri] (a previously-written envelope) with
     * [passphrase] and write the recovered plaintext to [outputUri].
     */
    fun decryptFromEnvelope(
        ctx: Context,
        inputUri: Uri,
        outputUri: Uri,
        passphrase: CharArray,
    ): Result {
        val key = AesGcmPassphraseCodec.PassphraseKey(passphrase)
        var plaintext: ByteArray? = null
        try {
            val parsed = ctx.contentResolver.openInputStream(inputUri).use { input ->
                requireNotNull(input) { "couldn't open input stream" }
                BackupEnvelope.parse(input)
            }
            plaintext = BackupEnvelope.decryptPayload(parsed, AesGcmPassphraseCodec, key)
            ctx.contentResolver.openOutputStream(outputUri, "w").use { out ->
                requireNotNull(out) { "couldn't open output stream" }
                out.write(plaintext)
            }
            return Result.Success(
                "Decrypted ${plaintext.size} bytes → plaintext at chosen location. " +
                    "Header label: \"${parsed.header.label}\".",
            )
        } catch (t: Throwable) {
            return Result.Failure(
                "Decrypt failed: ${t.message ?: t.javaClass.simpleName}. " +
                    "Most likely cause is a wrong passphrase; the envelope's " +
                    "AES-GCM tag rejects an incorrect key.",
            )
        } finally {
            key.wipe()
            plaintext?.let { Crypto.wipe(it) }
        }
    }

    /**
     * Encrypt the bytes at [inputUri] with [passphrase] and write the
     * resulting envelope to [outputFile] on local internal storage.
     * Sibling of [encryptToEnvelope] but the destination is a local
     * [File] reserved by [LocalSnapshotStore.reserveNew] instead of a
     * SAF-picked URI.
     */
    fun encryptToLocalSnapshot(
        ctx: Context,
        inputUri: Uri,
        outputFile: File,
        appLabel: String,
        userLabel: String,
        passphrase: CharArray,
    ): Result {
        val plaintext: ByteArray = try {
            readBoundedBytes(ctx, inputUri)
        } catch (t: Throwable) {
            return Result.Failure("Couldn't read input: ${t.message ?: t.javaClass.simpleName}")
        }

        val key = AesGcmPassphraseCodec.PassphraseKey(passphrase)
        try {
            val header = BackupEnvelope.Header(
                appId = appLabel,
                schemaVersion = 1,
                createdAtMs = System.currentTimeMillis(),
                label = userLabel,
                codecParams = emptyMap(),
            )
            FileOutputStream(outputFile).use { out ->
                BackupEnvelope.write(
                    out = out,
                    codec = AesGcmPassphraseCodec,
                    header = header,
                    plaintext = plaintext,
                    codecKey = key,
                )
            }
        } catch (t: Throwable) {
            // Drop the partial file so list() doesn't surface a broken entry.
            runCatching { outputFile.delete() }
            Crypto.wipe(plaintext)
            return Result.Failure("Encrypt failed: ${t.message ?: t.javaClass.simpleName}")
        } finally {
            key.wipe()
        }
        val written = outputFile.length()
        Crypto.wipe(plaintext)
        return Result.Success("Encrypted ${plaintext.size} bytes → $written-byte snapshot at ${outputFile.name}.")
    }

    /**
     * Decrypt the local snapshot at [snapshotFile] with [passphrase]
     * and write the recovered plaintext to [outputUri]. Sibling of
     * [decryptFromEnvelope] but the input is a local [File] from
     * [LocalSnapshotStore.list] instead of a SAF-picked URI.
     */
    fun decryptLocalSnapshot(
        ctx: Context,
        snapshotFile: File,
        outputUri: Uri,
        passphrase: CharArray,
    ): Result {
        val key = AesGcmPassphraseCodec.PassphraseKey(passphrase)
        var plaintext: ByteArray? = null
        try {
            val parsed = FileInputStream(snapshotFile).use { input ->
                BackupEnvelope.parse(input)
            }
            plaintext = BackupEnvelope.decryptPayload(parsed, AesGcmPassphraseCodec, key)
            ctx.contentResolver.openOutputStream(outputUri, "w").use { out ->
                requireNotNull(out) { "couldn't open output stream" }
                out.write(plaintext)
            }
            return Result.Success(
                "Decrypted ${plaintext.size} bytes → plaintext at chosen location. " +
                    "Header label: \"${parsed.header.label}\".",
            )
        } catch (t: Throwable) {
            return Result.Failure(
                "Decrypt failed: ${t.message ?: t.javaClass.simpleName}. " +
                    "Wrong passphrase, or the snapshot file is corrupted.",
            )
        } finally {
            key.wipe()
            plaintext?.let { Crypto.wipe(it) }
        }
    }

    private fun readBoundedBytes(ctx: Context, uri: Uri): ByteArray {
        ctx.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "couldn't open input stream" }
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var total = 0
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                require(total <= MAX_INPUT_SIZE) {
                    "input too large (>${MAX_INPUT_SIZE / (1024 * 1024)} MiB); " +
                        "backups are designed for vault-sized data"
                }
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }
}
