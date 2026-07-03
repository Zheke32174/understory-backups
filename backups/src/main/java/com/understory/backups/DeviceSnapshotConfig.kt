package com.understory.backups

import android.content.Context

/**
 * Device-wide snapshot configuration. Per-section toggles + destination
 * preference, persisted via SharedPreferences. Read by [DeviceSnapshotService]
 * at the start of each snapshot run; UI ([DeviceSnapshotConfigScreen])
 * mutates these via the setters.
 *
 * Sections + their current support level:
 *
 * - androidSettings: user-readable Settings.System / Settings.Secure /
 *   Settings.Global keys, serialized as JSON. WORKING (small, fits in
 *   memory; written into a single BackupEnvelope alongside other small
 *   sections).
 *
 * - standardUserDirs: Pictures / Downloads / Documents / Music /
 *   Movies / DCIM. WORKING-AS-MANIFEST: this commit emits a manifest
 *   of (path, size, mtime) tuples, NOT file contents. Full-content
 *   backup needs streaming AES-GCM encryption (chunked, per-block
 *   tag) + a foreground worker that can write multi-GB to a SAF
 *   tree URI without OOM. That's Wave B-2.
 *
 * - suiteAppVaults: passgen + aegis vaults via cross-app
 *   BackupContentProvider. STUBBED: each suite app needs a
 *   signature-locked content provider that exposes its
 *   BackupAdapter.export(). Wave B-2.
 *
 * - vaultFolderSecureFiles: vault-folder's encrypted blobs. STUBBED
 *   for the same cross-app reason. Wave B-2.
 *
 * Destination is either internal (filesDir/snapshots/, written via
 * LocalSnapshotStore — capped by app quota) or a SAF-picked tree URI
 * (typically /storage/emulated/0/Backups; user persists the URI grant
 * via takePersistableUriPermission so we can write across reboots).
 */
data class DeviceSnapshotConfig(
    val includeStandardUserDirs: Boolean,
    val includeSuiteAppVaults: Boolean,
    val includeAndroidSettings: Boolean,
    val includeVaultFolderSecureFiles: Boolean,
    /**
     * Sub-toggle of [includeStandardUserDirs]. When true, the snapshot
     * writes a second file (`device-<ts>.usbs`) containing the actual
     * file contents, encrypted with the streaming AES-GCM codec. When
     * false (default), only the manifest goes in the main envelope.
     *
     * Default false because content snapshots can be multi-GiB and
     * users should consciously opt in. The UI banner explains the
     * size implications + the SAF tree URI requirement (the FGS
     * caps writes to internal storage at the OS-imposed app quota,
     * which most users will exceed for a full Pictures dir).
     */
    val includeUserDirContent: Boolean,
    /** Stringified SAF tree URI, or null = write to internal storage. */
    val destinationTreeUri: String?,
) {
    /** True iff at least one section is enabled. UI uses this to gate
     *  the "Snapshot now" button. */
    val anyEnabled: Boolean
        get() = includeStandardUserDirs ||
            includeSuiteAppVaults ||
            includeAndroidSettings ||
            includeVaultFolderSecureFiles

    companion object {
        private const val PREF = "device_snapshot_config"
        private const val K_USER_DIRS = "include_standard_user_dirs"
        private const val K_SUITE_VAULTS = "include_suite_app_vaults"
        private const val K_ANDROID_SETTINGS = "include_android_settings"
        private const val K_VAULT_FOLDER = "include_vault_folder_secure_files"
        private const val K_USER_DIR_CONTENT = "include_user_dir_content"
        private const val K_DEST_URI = "destination_tree_uri"

        fun load(ctx: Context): DeviceSnapshotConfig {
            val p = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            return DeviceSnapshotConfig(
                // Defaults: section toggles on (manifest-only is cheap),
                // content opt-in (off by default — multi-GiB), no
                // destination URI (forces user choice on first run).
                includeStandardUserDirs = p.getBoolean(K_USER_DIRS, true),
                // Stub sections default OFF (backups.md §10, D-13): until the
                // deposit-intent collect mechanism (§3) lands, these sections
                // have no real data to contribute and are hidden entirely by
                // the config screen. Defaulting them false means a fresh install
                // never writes a "pending" stub.
                includeSuiteAppVaults = p.getBoolean(K_SUITE_VAULTS, false),
                includeAndroidSettings = p.getBoolean(K_ANDROID_SETTINGS, true),
                includeVaultFolderSecureFiles = p.getBoolean(K_VAULT_FOLDER, false),
                includeUserDirContent = p.getBoolean(K_USER_DIR_CONTENT, false),
                destinationTreeUri = p.getString(K_DEST_URI, null),
            )
        }

        fun save(ctx: Context, cfg: DeviceSnapshotConfig) {
            ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE).edit().apply {
                putBoolean(K_USER_DIRS, cfg.includeStandardUserDirs)
                putBoolean(K_SUITE_VAULTS, cfg.includeSuiteAppVaults)
                putBoolean(K_ANDROID_SETTINGS, cfg.includeAndroidSettings)
                putBoolean(K_VAULT_FOLDER, cfg.includeVaultFolderSecureFiles)
                putBoolean(K_USER_DIR_CONTENT, cfg.includeUserDirContent)
                if (cfg.destinationTreeUri != null) putString(K_DEST_URI, cfg.destinationTreeUri)
                else remove(K_DEST_URI)
            }.apply()
        }
    }
}
