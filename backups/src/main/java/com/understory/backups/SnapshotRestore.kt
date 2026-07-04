package com.understory.backups

import android.content.Context
import com.understory.elevation.Elevation
import com.understory.elevation.Outcome
import com.understory.security.Diagnostics
import java.util.Locale

/**
 * GUIDED restore from a device-posture [SnapshotCapture.Snapshot].
 *
 * Two deliberately-different restore modes, both fail-closed and honest:
 *
 *  1. APP INVENTORY — a *guided list*, NEVER a silent reinstall. We surface the
 *     captured packages that are not currently installed so the user can
 *     reinstall each one themselves via the store. This module only computes the
 *     "missing" set and hands out per-app store links; it installs nothing.
 *
 *  2. SETTINGS — per-key, opt-in `settings put` for a SMALL SAFE allowlist only,
 *     with the live current value shown as a diff before any write. Each write
 *     returns an [Outcome]; per-key rejections ([Outcome.Failed]) are surfaced
 *     honestly rather than swallowed. Nothing here touches a key outside
 *     [RESTORABLE_KEYS].
 *
 * Hard-exclude: we never target the launcher, com.android.settings, Tailscale,
 * Shizuku/Sui managers, or any com.understory.* sibling — those are filtered out
 * of the guided reinstall list so a restore flow can't nudge the user to touch a
 * suite sibling or a load-bearing system app.
 */
object SnapshotRestore {

    /** Packages we never surface in the guided reinstall list (see class doc). */
    private val EXCLUDED_PREFIXES = listOf(
        "com.understory.", // every suite sibling
    )
    private val EXCLUDED_EXACT = setOf(
        "com.android.settings",
        "com.tailscale.ipn",
        "moe.shizuku.privileged.api", // Shizuku
        "moe.shizuku.manager",
        "rikka.sui", // Sui manager
    )

    /**
     * The ONLY settings keys restore may write. Each carries its namespace and a
     * one-line human description for the diff UI. Intentionally a small,
     * benign, non-secret set — screen brightness, font scale, ring/notification
     * volume, and the 12/24-hour time format.
     */
    data class RestorableKey(
        val namespace: String, // "system" | "global" | "secure"
        val key: String,
        val label: String,
    )

    val RESTORABLE_KEYS: List<RestorableKey> = listOf(
        RestorableKey("system", "screen_brightness", "Screen brightness"),
        RestorableKey("system", "screen_brightness_mode", "Adaptive brightness on/off"),
        RestorableKey("system", "font_scale", "Font scale"),
        RestorableKey("system", "time_12_24", "12/24-hour clock"),
        RestorableKey("system", "volume_ring", "Ring volume"),
        RestorableKey("system", "volume_notification", "Notification volume"),
    )

    private val RESTORABLE_INDEX: Map<Pair<String, String>, RestorableKey> =
        RESTORABLE_KEYS.associateBy { it.namespace to it.key }

    // ---- App-inventory guided restore ---------------------------------------

    /** One captured app the user might want to reinstall. */
    data class MissingApp(
        val packageName: String,
        val versionName: String?,
        val installer: String?,
    )

    /**
     * The captured packages that are NOT currently installed (and not excluded).
     * Purely informational — the caller renders a list and offers per-app store
     * links; nothing is installed here.
     */
    fun missingApps(ctx: Context, snapshot: SnapshotCapture.Snapshot): List<MissingApp> {
        val pm = ctx.packageManager
        val launcher = defaultLauncher(pm)
        return snapshot.packages
            .asSequence()
            .filter { it.packageName.isNotBlank() }
            .filterNot { isExcluded(it.packageName, launcher) }
            .filterNot { isInstalled(pm, it.packageName) }
            .map { MissingApp(it.packageName, it.versionName, it.installer) }
            .sortedBy { it.packageName }
            .toList()
    }

    /** The current default home/launcher package (OEM-specific — cannot be a
     *  static match), so it is excluded from the reinstall list at runtime. */
    private fun defaultLauncher(pm: android.content.pm.PackageManager): String? = runCatching {
        val home = android.content.Intent(android.content.Intent.ACTION_MAIN)
            .addCategory(android.content.Intent.CATEGORY_HOME)
        pm.resolveActivity(home, 0)?.activityInfo?.packageName
    }.getOrNull()

    private fun isExcluded(pkg: String, launcher: String?): Boolean {
        if (launcher != null && pkg == launcher) return true
        if (pkg in EXCLUDED_EXACT) return true
        return EXCLUDED_PREFIXES.any { pkg.startsWith(it) }
    }

    private fun isInstalled(pm: android.content.pm.PackageManager, pkg: String): Boolean =
        runCatching { pm.getPackageInfo(pkg, 0); true }.getOrDefault(false)

    // ---- Settings restore ---------------------------------------------------

    /** A single restorable setting with its captured and live-current values. */
    data class SettingDiff(
        val meta: RestorableKey,
        val capturedValue: String,
        val currentValue: String?, // null = couldn't read / not set
    ) {
        /** True when the captured value differs from what's live now. */
        val changed: Boolean get() = currentValue == null || currentValue != capturedValue
    }

    /**
     * Compute the restorable-settings diff: for every captured setting whose key
     * is on [RESTORABLE_KEYS], read the LIVE current value (read-only) and pair
     * it with the captured value. Keys not on the allowlist are dropped.
     * MUST be called off the main thread ([Elevation.readShell] is suspend-backed
     * but this reads live state).
     */
    suspend fun settingsDiff(ctx: Context, snapshot: SnapshotCapture.Snapshot): List<SettingDiff> {
        val out = ArrayList<SettingDiff>()
        for (entry in snapshot.settings) {
            val meta = RESTORABLE_INDEX[entry.namespace to entry.key] ?: continue
            val current = Elevation.readShell(ctx, listOf("settings", "get", entry.namespace, entry.key))
                ?.trim()?.takeIf { it.isNotBlank() && it != "null" }
            out += SettingDiff(meta, entry.value, current)
        }
        return out
    }

    /**
     * Write ONE allowlisted setting via `settings put <ns> <key> <value>`.
     * Fail-closed: refuses any key not on [RESTORABLE_KEYS] and any value that
     * doesn't validate for its key ([isValueSafe]). Returns the elevation
     * [Outcome] verbatim so the UI can surface a per-key rejection honestly.
     */
    suspend fun restoreSetting(ctx: Context, diff: SettingDiff): Outcome {
        val meta = diff.meta
        // Re-check the allowlist at the write boundary (defense in depth).
        if (RESTORABLE_INDEX[meta.namespace to meta.key] == null) {
            return Outcome.Failed("Refused: ${meta.key} is not a restorable setting")
        }
        val value = diff.capturedValue.trim()
        if (!isValueSafe(meta, value)) {
            return Outcome.Failed("Refused: value \"$value\" is out of range for ${meta.label}")
        }
        if (!Elevation.canRunShell(ctx)) {
            return Outcome.Unsupported("Settings restore needs Shizuku; grant it to enable this.")
        }
        return Elevation.readShellOrPut(ctx, meta.namespace, meta.key, value)
    }

    /**
     * Value validation per key. We only ever pass numeric-or-known-token values
     * so a captured (or drifted) value can't smuggle a shell surprise. Anything
     * non-conforming is refused rather than written.
     */
    private fun isValueSafe(meta: RestorableKey, value: String): Boolean {
        if (value.isEmpty() || value.length > 12) return false
        return when (meta.key) {
            // Booleans / small enums.
            "screen_brightness_mode", "time_12_24" -> value in setOf("0", "1", "12", "24")
            // Non-negative integers (brightness 0..255, volumes 0..~30).
            "screen_brightness", "volume_ring", "volume_notification" ->
                value.toIntOrNull()?.let { it in 0..255 } == true
            // font_scale is a small positive float like "1.0".
            "font_scale" -> value.toFloatOrNull()?.let { it in 0.5f..2.0f } == true
            else -> false
        }
    }
}

/**
 * Thin, self-contained privileged `settings put` for the restore path. The
 * shared [Elevation] object exposes many typed helpers but not a generic
 * settings-put; rather than widen its API surface, restore issues its OWN
 * guarded put through the same READ-ONLY-by-default broker's low-level shell,
 * translating the result to an [Outcome]. Args are passed as separate argv
 * elements — never a joined shell string — so there is no interpolation.
 *
 * This is defined as an extension in this file (not in the vendored module) to
 * keep the elevation module untouched; it still goes through
 * [Elevation.runShell], which throws [com.understory.elevation.NotElevated] when
 * unelevated — caught and mapped here so nothing throws to the UI.
 */
private suspend fun Elevation.readShellOrPut(
    ctx: Context,
    namespace: String,
    key: String,
    value: String,
): Outcome = try {
    val r = runShell(ctx, listOf("settings", "put", namespace, key, value))
    if (r.ok) {
        Diagnostics.log("backups.SnapshotRestore", "put $namespace/$key ok")
        Outcome.Success("$key set")
    } else {
        Outcome.Failed("write rejected (exit ${r.exit}): ${r.err.trim().take(160)}")
    }
} catch (e: com.understory.elevation.NotElevated) {
    Outcome.Unsupported(e.message ?: "not elevated")
} catch (t: Throwable) {
    Outcome.Failed("write failed: ${t.message ?: t.javaClass.simpleName}", t)
}
