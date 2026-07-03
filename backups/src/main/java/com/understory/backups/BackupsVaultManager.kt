package com.understory.backups

/**
 * Process-singleton holding the currently-unlocked backups vault, if
 * any. Same shape as VaultFolderManager / AegisVaultManager — lets
 * Compose screens read the unlocked KEK without re-prompting biometric
 * on every operation.
 *
 * Also tracks "transient flight" — deliberate round-trips to the SAF
 * picker, biometric prompt, etc. — so the activity's onStop can
 * preserve the unlocked vault across the brief stop. Without this,
 * Samsung One UI's aggressive memory management nulls the vault
 * during a SAF round-trip and the user finds themselves bounced back
 * to the Unlock screen with no SAF result delivered.
 */
object BackupsVaultManager {
    @Volatile private var unlocked: UnlockedBackupsVault? = null

    val current: UnlockedBackupsVault? get() = unlocked
    val isUnlocked: Boolean get() = unlocked != null

    fun setUnlocked(vault: UnlockedBackupsVault) {
        unlocked = vault
    }

    fun clear() {
        runCatching { unlocked?.lock() }
        unlocked = null
    }

    @Volatile private var transientFlightCount = 0
    private val flightLock = Any()

    /**
     * Mark a deliberate transient occlusion (SAF picker, biometric prompt).
     * While this count is > 0, the activity's onStop preserves the unlocked
     * vault rather than wiping it — the user returning from the picker still
     * has their session.
     */
    fun beginTransientFlight() {
        synchronized(flightLock) { transientFlightCount++ }
    }

    fun endTransientFlight() {
        synchronized(flightLock) { if (transientFlightCount > 0) transientFlightCount-- }
    }

    val isInTransientFlight: Boolean
        get() = synchronized(flightLock) { transientFlightCount > 0 }
}
