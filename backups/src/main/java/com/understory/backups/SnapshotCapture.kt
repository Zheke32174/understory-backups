package com.understory.backups

import android.content.Context
import com.understory.elevation.Elevation
import com.understory.security.Diagnostics
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Elevated device-POSTURE snapshot capture (backups "Device snapshot").
 *
 * This is strictly COMPLEMENTARY to the self-sealing backup envelope: the
 * envelope captures your app/vault DATA; this captures the device's *posture* —
 * the installed-app inventory (versions, installer, granted perms + appop modes)
 * and a small allowlist of benign, non-secret user-tunable settings — so that
 * after a wipe you can see what you had and reinstall/re-tune deliberately.
 *
 * Every read is via [Elevation.readShell], which is READ-ONLY and returns null
 * when unelevated or on any error. We parse DEFENSIVELY and fail OPEN: a parse
 * miss or a dump-format drift degrades to fewer captured fields, never an
 * exception and never a fabricated value. Nothing here writes device state.
 *
 * Persistence is a plain JSON file in the app's PRIVATE filesDir (not the
 * encrypted vault): this is device posture, not vault secrets, and keeping it
 * unencrypted lets the guided-restore list open without unlocking crypto. The
 * settings allowlist deliberately excludes anything token/key/account-shaped.
 */
object SnapshotCapture {

    // ---- Settings allowlist (benign, NON-secret, user-tunable) --------------
    // We ONLY capture these keys. Everything else — and anything that even looks
    // like a secret — is never read. Restore (SnapshotRestore) further narrows
    // to a writable subset; capture is a superset for informational display.

    /** `settings get global <key>` — benign global tunables. */
    val GLOBAL_ALLOWLIST: List<String> = listOf(
        "auto_time",
        "auto_time_zone",
        "wifi_sleep_policy",
        "airplane_mode_on",
        "bluetooth_on",
        "wifi_on",
    )

    /** `settings get secure <key>` — benign per-user tunables (no tokens/keys). */
    val SECURE_ALLOWLIST: List<String> = listOf(
        "screen_off_timeout",
        "accessibility_display_magnification_enabled",
        "long_press_timeout",
        "font_scale",
    )

    /** `settings get system <key>` — benign system tunables. */
    val SYSTEM_ALLOWLIST: List<String> = listOf(
        "screen_brightness",
        "screen_brightness_mode",
        "font_scale",
        "time_12_24",
        "volume_ring",
        "volume_notification",
        "vibrate_when_ringing",
        "haptic_feedback_enabled",
        "dtmf_tone",
        "sound_effects_enabled",
    )

    /** Reject any key that smells secret even if it slipped onto an allowlist. */
    private val SECRET_HINTS = listOf(
        "token", "key", "secret", "password", "passwd", "account", "credential",
        "auth", "session", "cookie", "certificate", "android_id", "imei", "serial",
    )

    private fun isSecretShaped(key: String): Boolean {
        val k = key.lowercase(Locale.US)
        return SECRET_HINTS.any { k.contains(it) }
    }

    // ---- Captured model -----------------------------------------------------

    /** One captured package: identity + posture. All fields best-effort. */
    data class PackageEntry(
        val packageName: String,
        val apkPath: String?,
        val versionCode: String?,
        val versionName: String?,
        val installer: String?,
        val grantedPermissions: List<String>,
        val appOps: Map<String, String>,
    )

    /** One captured setting: value plus its shell namespace, tagged shell-origin. */
    data class SettingEntry(
        val namespace: String, // "global" | "secure" | "system"
        val key: String,
        val value: String,
    )

    /** A full device-posture snapshot. */
    data class Snapshot(
        val capturedAtMs: Long,
        val androidRelease: String,
        val packages: List<PackageEntry>,
        val settings: List<SettingEntry>,
    ) {
        fun formattedTimestamp(): String =
            SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(capturedAtMs))
    }

    /** Coarse progress for the UI while a capture runs. */
    data class Progress(val phase: String, val done: Int, val total: Int)

    // ---- Capture ------------------------------------------------------------

    /**
     * Capture a device-posture snapshot. MUST be called off the main thread.
     * Gated by the caller on [Elevation.canRunShell]; if elevation is lost
     * mid-capture every read degrades to null and the snapshot simply carries
     * fewer entries. Never throws.
     *
     * @param onProgress optional coarse progress callback (phase, done, total).
     */
    suspend fun capture(
        ctx: Context,
        onProgress: (Progress) -> Unit = {},
    ): Snapshot {
        val started = System.currentTimeMillis()
        Diagnostics.log("backups.SnapshotCapture", "capture start")

        val packages = runCatching { captureInventory(ctx, onProgress) }
            .getOrElse {
                Diagnostics.error("backups.SnapshotCapture", "inventory failed: ${it.message}")
                emptyList()
            }
        val settings = runCatching { captureSettings(ctx, onProgress) }
            .getOrElse {
                Diagnostics.error("backups.SnapshotCapture", "settings failed: ${it.message}")
                emptyList()
            }

        val release = android.os.Build.VERSION.RELEASE ?: "unknown"
        Diagnostics.log(
            "backups.SnapshotCapture",
            "capture done: ${packages.size} pkgs, ${settings.size} settings",
        )
        return Snapshot(
            capturedAtMs = started,
            androidRelease = release,
            packages = packages.sortedBy { it.packageName },
            settings = settings,
        )
    }

    /**
     * `pm list packages -f` → one `package:<path>=<pkg>` line per app, then a
     * per-package `dumpsys package <pkg>` parsed defensively for versionCode,
     * installer, granted runtime perms and appop modes.
     */
    private suspend fun captureInventory(
        ctx: Context,
        onProgress: (Progress) -> Unit,
    ): List<PackageEntry> {
        val listing = Elevation.readShell(ctx, listOf("pm", "list", "packages", "-f")) ?: return emptyList()
        val pathByPkg = LinkedHashMap<String, String?>()
        listing.lineSequence().forEach { raw ->
            val line = raw.trim()
            if (!line.startsWith("package:")) return@forEach
            // Format: package:<apkPath>=<packageName>. The '=' separates path
            // from pkg; a path can itself contain '=' only rarely, so split on
            // the LAST '=' to recover the package name robustly.
            val body = line.removePrefix("package:")
            val eq = body.lastIndexOf('=')
            if (eq <= 0 || eq == body.length - 1) {
                // No path form (some ROMs emit `package:<pkg>`); record pkg-only.
                val pkgOnly = body.substringAfterLast('=').ifBlank { body }
                if (pkgOnly.isNotBlank()) pathByPkg.putIfAbsent(pkgOnly, null)
                return@forEach
            }
            val path = body.substring(0, eq)
            val pkg = body.substring(eq + 1)
            if (pkg.isNotBlank()) pathByPkg.putIfAbsent(pkg, path.ifBlank { null })
        }

        val pkgs = pathByPkg.keys.toList()
        val total = pkgs.size
        val out = ArrayList<PackageEntry>(total)
        pkgs.forEachIndexed { i, pkg ->
            onProgress(Progress("Inventorying apps", i, total))
            val dump = Elevation.readShell(ctx, listOf("dumpsys", "package", pkg))
            out += parsePackageDump(pkg, pathByPkg[pkg], dump)
        }
        onProgress(Progress("Inventorying apps", total, total))
        return out
    }

    /**
     * Defensive parse of `dumpsys package <pkg>`. Any field that isn't found is
     * left null / empty — we never fabricate. Resilient to line reordering and
     * whitespace drift across OEM ROMs.
     */
    internal fun parsePackageDump(pkg: String, apkPath: String?, dump: String?): PackageEntry {
        if (dump.isNullOrBlank()) {
            return PackageEntry(pkg, apkPath, null, null, null, emptyList(), emptyMap())
        }
        var versionCode: String? = null
        var versionName: String? = null
        var installer: String? = null
        val granted = LinkedHashSet<String>()
        val appOps = LinkedHashMap<String, String>()

        dump.lineSequence().forEach { raw ->
            val line = raw.trim()
            when {
                versionCode == null && line.startsWith("versionCode=") -> {
                    // "versionCode=1234 minSdk=… targetSdk=…" — take the first token.
                    versionCode = line.removePrefix("versionCode=")
                        .substringBefore(' ').takeIf { it.isNotBlank() }
                }
                versionName == null && line.startsWith("versionName=") -> {
                    versionName = line.removePrefix("versionName=")
                        .substringBefore(' ').takeIf { it.isNotBlank() }
                }
                installer == null && line.startsWith("installerPackageName=") -> {
                    installer = line.removePrefix("installerPackageName=")
                        .substringBefore(' ').takeIf { it.isNotBlank() && it != "null" }
                }
                // Granted runtime permission lines look like:
                //   android.permission.CAMERA: granted=true
                line.startsWith("android.permission.") && line.contains("granted=true") -> {
                    granted += line.substringBefore(':').trim()
                }
                // AppOps blocks emit lines like "CAMERA: allow" or
                // "COARSE_LOCATION: mode=ignore". Capture a compact "op → mode".
                else -> {
                    val op = APPOP_LINE.matchEntire(line)
                    if (op != null) {
                        val name = op.groupValues[1]
                        val mode = op.groupValues[2].ifBlank { op.groupValues[3] }
                        if (name.isNotBlank() && mode.isNotBlank()) {
                            appOps.putIfAbsent(name, mode)
                        }
                    }
                }
            }
        }
        return PackageEntry(
            packageName = pkg,
            apkPath = apkPath,
            versionCode = versionCode,
            versionName = versionName,
            installer = installer,
            grantedPermissions = granted.toList(),
            appOps = appOps,
        )
    }

    // Matches "OP_NAME: allow" or "OP_NAME: mode=ignore" (uppercase op names).
    private val APPOP_LINE = Regex("^([A-Z][A-Z0-9_]{2,}):\\s*(?:mode=)?(allow|ignore|deny|default|foreground)?\\s*(allow|ignore|deny|default|foreground)?.*$")

    /**
     * Capture allowlisted settings across the three namespaces via
     * `settings get <ns> <key>`. Secret-shaped keys are refused even if present
     * on an allowlist. A null/blank/"null" read is simply omitted (fail-open).
     */
    private suspend fun captureSettings(
        ctx: Context,
        onProgress: (Progress) -> Unit,
    ): List<SettingEntry> {
        val plan = buildList {
            GLOBAL_ALLOWLIST.forEach { add("global" to it) }
            SECURE_ALLOWLIST.forEach { add("secure" to it) }
            SYSTEM_ALLOWLIST.forEach { add("system" to it) }
        }.filterNot { isSecretShaped(it.second) }

        val total = plan.size
        val out = ArrayList<SettingEntry>(total)
        plan.forEachIndexed { i, (ns, key) ->
            onProgress(Progress("Reading settings", i, total))
            val v = Elevation.readShell(ctx, listOf("settings", "get", ns, key))
            val value = v?.trim()
            if (!value.isNullOrBlank() && value != "null") {
                out += SettingEntry(ns, key, value)
            }
        }
        onProgress(Progress("Reading settings", total, total))
        return out
    }

    // ---- Persistence (private filesDir, plain JSON) -------------------------

    private const val DIR = "device_posture"

    private fun dir(ctx: Context): File =
        File(ctx.filesDir, DIR).apply { if (!exists()) mkdirs() }

    /** Newest-first list of persisted snapshot files (posture-<utc>.json). */
    fun listFiles(ctx: Context): List<File> {
        val files = dir(ctx).listFiles { f -> f.isFile && f.name.endsWith(".json") }
            ?: return emptyList()
        return files.sortedByDescending { it.lastModified() }
    }

    /** Metadata-only header for the list UI (parses without loading everything). */
    data class Header(val file: File, val capturedAtMs: Long, val packageCount: Int, val settingCount: Int) {
        fun formattedTimestamp(): String =
            SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(capturedAtMs))
    }

    fun headers(ctx: Context): List<Header> = listFiles(ctx).mapNotNull { f ->
        runCatching {
            val obj = JSONObject(f.readText())
            Header(
                file = f,
                capturedAtMs = obj.optLong("capturedAtMs", f.lastModified()),
                packageCount = obj.optJSONArray("packages")?.length() ?: 0,
                settingCount = obj.optJSONArray("settings")?.length() ?: 0,
            )
        }.getOrNull()
    }

    /** Persist a snapshot as plain JSON. Returns the written file, or null on IO failure. */
    fun save(ctx: Context, snapshot: Snapshot): File? = runCatching {
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US)
            .apply { timeZone = TimeZone.getTimeZone("UTC") }
            .format(Date(snapshot.capturedAtMs))
        val file = File(dir(ctx), "posture-$ts.json")
        file.writeText(toJson(snapshot).toString())
        file
    }.getOrElse {
        Diagnostics.error("backups.SnapshotCapture", "save failed: ${it.message}")
        null
    }

    /** Load a snapshot back from a persisted file. Null on parse failure (fail-open). */
    fun load(file: File): Snapshot? = runCatching { fromJson(JSONObject(file.readText())) }.getOrNull()

    fun delete(file: File): Boolean = runCatching { file.delete() }.getOrDefault(false)

    // ---- JSON (org.json, no external dep) -----------------------------------

    private fun toJson(s: Snapshot): JSONObject {
        val pkgs = JSONArray()
        s.packages.forEach { p ->
            val ops = JSONObject()
            p.appOps.forEach { (k, v) -> ops.put(k, v) }
            pkgs.put(
                JSONObject()
                    .put("packageName", p.packageName)
                    .put("apkPath", p.apkPath ?: JSONObject.NULL)
                    .put("versionCode", p.versionCode ?: JSONObject.NULL)
                    .put("versionName", p.versionName ?: JSONObject.NULL)
                    .put("installer", p.installer ?: JSONObject.NULL)
                    .put("grantedPermissions", JSONArray(p.grantedPermissions))
                    .put("appOps", ops),
            )
        }
        val settings = JSONArray()
        s.settings.forEach { e ->
            settings.put(
                JSONObject()
                    .put("namespace", e.namespace)
                    .put("key", e.key)
                    .put("value", e.value)
                    .put("origin", "shell"),
            )
        }
        return JSONObject()
            .put("schema", 1)
            .put("capturedAtMs", s.capturedAtMs)
            .put("androidRelease", s.androidRelease)
            .put("packages", pkgs)
            .put("settings", settings)
    }

    private fun fromJson(obj: JSONObject): Snapshot {
        val pkgs = ArrayList<PackageEntry>()
        obj.optJSONArray("packages")?.let { arr ->
            for (i in 0 until arr.length()) {
                val p = arr.optJSONObject(i) ?: continue
                val perms = ArrayList<String>()
                p.optJSONArray("grantedPermissions")?.let { pa ->
                    for (j in 0 until pa.length()) pa.optString(j).takeIf { it.isNotBlank() }?.let(perms::add)
                }
                val ops = LinkedHashMap<String, String>()
                p.optJSONObject("appOps")?.let { oo ->
                    val keys = oo.keys()
                    while (keys.hasNext()) { val k = keys.next(); ops[k] = oo.optString(k) }
                }
                pkgs += PackageEntry(
                    packageName = p.optString("packageName"),
                    apkPath = p.optStringOrNull("apkPath"),
                    versionCode = p.optStringOrNull("versionCode"),
                    versionName = p.optStringOrNull("versionName"),
                    installer = p.optStringOrNull("installer"),
                    grantedPermissions = perms,
                    appOps = ops,
                )
            }
        }
        val settings = ArrayList<SettingEntry>()
        obj.optJSONArray("settings")?.let { arr ->
            for (i in 0 until arr.length()) {
                val e = arr.optJSONObject(i) ?: continue
                val ns = e.optString("namespace")
                val key = e.optString("key")
                val value = e.optString("value")
                if (ns.isNotBlank() && key.isNotBlank()) settings += SettingEntry(ns, key, value)
            }
        }
        return Snapshot(
            capturedAtMs = obj.optLong("capturedAtMs", 0L),
            androidRelease = obj.optString("androidRelease", "unknown"),
            packages = pkgs,
            settings = settings,
        )
    }

    private fun JSONObject.optStringOrNull(name: String): String? {
        if (isNull(name)) return null
        val v = optString(name, "")
        return v.takeIf { it.isNotBlank() && it != "null" }
    }
}
