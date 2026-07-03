package com.understory.backups

import android.content.Context
import android.provider.Settings
import com.understory.security.Diagnostics
import org.json.JSONObject

/**
 * Snapshot a stable subset of user-readable Android settings. Returns
 * a JSON string suitable for inclusion in a device snapshot envelope.
 *
 * What we include:
 *
 *   Settings.System.*    user-tunable per-device (volumes, brightness,
 *                        sound profiles, font scale, accelerometer
 *                        rotation, time format)
 *   Settings.Secure.*    accessibility-flavored (touch exploration on,
 *                        captioning, color inversion). Most security-
 *                        sensitive Settings.Secure keys are NOT
 *                        third-party-readable on Android 6+; we just
 *                        try each candidate and skip on null.
 *   Settings.Global.*    minimal set: airplane mode, mode ringer,
 *                        device-name (if readable). Most Global keys
 *                        are protected from third-party apps; same
 *                        skip-on-null behavior.
 *
 * What we DON'T include:
 *
 *   - Wi-Fi networks + passphrases (NETWORK_SETTINGS permission, signature-only)
 *   - VPN configurations (signature-only)
 *   - Location settings (LOCATION_BYPASS, signature-only)
 *   - Bluetooth pairings (BLUETOOTH_PRIVILEGED, signature-only)
 *   - APN settings, MMS configs (READ_PRIVILEGED_PHONE_STATE)
 *   - Contacts/Calendar/Call log (their own permissions; not
 *     "settings", but users sometimes assume backups cover them)
 *
 * The honest scope is "what a non-system app on a stock device can
 * read." Users should be told this explicitly so they don't rely on
 * the backup for things it can't capture. The backups screen
 * surfaces a one-line summary of skipped categories.
 *
 * Threat model: settings keys + values are stored cleartext inside the
 * encrypted snapshot envelope. The envelope's AES-GCM seal protects
 * them at rest; the backup destination (filesDir or SAF tree) is
 * trusted to the same level as the device's storage encryption.
 */
object AndroidSettingsCollector {

    /** Each tier's keys are tried in order; missing values are skipped
     *  (null returns) so the same code works on devices where some
     *  keys are protected. */
    private val SYSTEM_KEYS = listOf(
        Settings.System.TEXT_SHOW_PASSWORD,
        Settings.System.SCREEN_BRIGHTNESS,
        Settings.System.SCREEN_BRIGHTNESS_MODE,
        Settings.System.SCREEN_OFF_TIMEOUT,
        Settings.System.SOUND_EFFECTS_ENABLED,
        Settings.System.HAPTIC_FEEDBACK_ENABLED,
        Settings.System.VIBRATE_WHEN_RINGING,
        Settings.System.RINGTONE,
        Settings.System.NOTIFICATION_SOUND,
        Settings.System.ALARM_ALERT,
        Settings.System.TIME_12_24,
        Settings.System.DATE_FORMAT,
        Settings.System.ACCELEROMETER_ROTATION,
        Settings.System.FONT_SCALE,
    )

    private val SECURE_KEYS = listOf(
        Settings.Secure.ACCESSIBILITY_ENABLED,
        Settings.Secure.TOUCH_EXPLORATION_ENABLED,
        Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        Settings.Secure.ACCESSIBILITY_DISPLAY_INVERSION_ENABLED,
        // The next four are valid Settings.Secure keys on real devices
        // but the corresponding constants don't exist on every
        // compileSdk's android.provider.Settings.Secure. Settings.Secure
        // .getString takes a String key, so the literal name works
        // regardless. Skip-on-null in the read loop covers devices
        // where the OS doesn't actually have the key.
        "accessibility_captioning_enabled",
        Settings.Secure.SKIP_FIRST_USE_HINTS,
        "high_text_contrast_enabled",
        "sleep_timeout",
        Settings.Secure.DEFAULT_INPUT_METHOD,
        Settings.Secure.ENABLED_INPUT_METHODS,
    )

    /** Settings.Global is mostly system-protected. We try a handful
     *  that have historically been third-party-readable. Most calls
     *  return null on modern Android; skip-on-null keeps the snapshot
     *  honest without throwing. */
    private val GLOBAL_KEYS = listOf(
        "device_name",  // Settings.Global.DEVICE_NAME, hidden constant
        "auto_time",
        "auto_time_zone",
        "airplane_mode_on",
        "wifi_on",
        "bluetooth_on",
        "mode_ringer",
    )

    fun collect(ctx: Context): String {
        val resolver = ctx.contentResolver
        val out = JSONObject()

        val system = JSONObject()
        for (k in SYSTEM_KEYS) {
            val v = runCatching { Settings.System.getString(resolver, k) }.getOrNull()
            if (v != null) system.put(k, v)
        }
        out.put("system", system)

        val secure = JSONObject()
        for (k in SECURE_KEYS) {
            val v = runCatching { Settings.Secure.getString(resolver, k) }.getOrNull()
            if (v != null) secure.put(k, v)
        }
        out.put("secure", secure)

        val global = JSONObject()
        for (k in GLOBAL_KEYS) {
            val v = runCatching { Settings.Global.getString(resolver, k) }.getOrNull()
            if (v != null) global.put(k, v)
        }
        out.put("global", global)

        out.put("collected_at_ms", System.currentTimeMillis())
        Diagnostics.log("backups.AndroidSettings",
            "collected: system=${system.length()} secure=${secure.length()} global=${global.length()}")
        return out.toString()
    }
}
