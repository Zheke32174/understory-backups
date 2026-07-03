package com.understory.backups

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Debug
import android.view.View
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.Button
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.backup.RecoveryFile
import com.understory.backups.BuildConfig
import com.understory.backups.R
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.TransientFlight
import com.understory.security.SecureOutlinedButton
import com.understory.security.ui.components.SuiteCard
import com.understory.security.ui.components.SuiteListRow
import com.understory.security.ui.components.SuiteScaffold
import com.understory.security.ui.components.SuiteSectionHeader
import com.understory.security.ui.theme.UnderstoryAccent
import com.understory.security.ui.theme.UnderstoryTheme
import com.understory.security.Tamper
import com.understory.security.TestingMode
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {

    private var unlocked: UnlockedBackupsVault?
        get() = BackupsVaultManager.current
        set(value) {
            if (value == null) BackupsVaultManager.clear()
            else BackupsVaultManager.setUnlocked(value)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        DiagnosticsDump.activateIfEng(this)
        super.onCreate(savedInstanceState)
        Diagnostics.log("backups.MainActivity", "onCreate (savedInstanceState=${savedInstanceState != null})")
        try {
            initialize()
        } catch (t: Throwable) {
            Diagnostics.error("backups.MainActivity", "onCreate threw: ${t.javaClass.simpleName}: ${t.message}")
            setContent {
                UnderstoryTheme(accent = UnderstoryAccent.BACKUPS) {
                    com.understory.security.ui.components.FatalScreen(
                        title = "backups couldn't start",
                        reason = "Something failed while initializing the app. Your " +
                            "encrypted data is untouched — this is a startup error, " +
                            "not a data loss. Reopen the app; if it recurs, the " +
                            "details below help diagnose it.",
                        details = t.toString(),
                    )
                }
            }
        }
    }

    private fun initialize() {
        val debuggerAttached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        if (debuggerAttached ||
            Tamper.check(applicationContext).hardFail ||
            com.understory.security.SuiteAttestation.verify(applicationContext).hardFail
        ) {
            finishAndRemoveTask(); return
        }

        if (!TestingMode.ALLOW_SCREENSHOTS) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                window.setHideOverlayWindows(true)
            }
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                setRecentsScreenshotEnabled(false)
            }
        }
        runCatching { WindowCompat.setDecorFitsSystemWindows(window, false) }

        // File-manager hand-off (§13): a `.usbe` opened from Files-by-Google
        // arrives as ACTION_VIEW with a content URI. We ONLY capture the URI —
        // never auto-decrypt; the user still unlocks and drives the Decrypt
        // screen, which pre-fills this input.
        val viewUri: Uri? = if (intent?.action == android.content.Intent.ACTION_VIEW) {
            intent?.data
        } else null

        setContent {
            UnderstoryTheme(accent = UnderstoryAccent.BACKUPS) {
                BackupsRoot(
                    activity = this,
                    unlockedRef = ::unlocked,
                    setUnlocked = { unlocked = it },
                    onClose = { finishAndRemoveTask() },
                    initialViewUri = viewUri,
                )
            }
        }
    }

    override fun onUserLeaveHint() {
        super.onUserLeaveHint()
        val inFlight = BackupsVaultManager.isInTransientFlight
        Diagnostics.log("backups.MainActivity",
            "onUserLeaveHint (inFlight=$inFlight, keepAlive=${TestingMode.KEEP_ALIVE_ON_LEAVE})")
        // Skip during a deliberate transient round-trip (SAF picker,
        // biometric prompt) — Samsung One UI fires onUserLeaveHint when
        // the SAF chooser opens.
        if (inFlight) return
        // Skip during the testing phase so the app stays alive across
        // switching apps. RELEASE-BLOCKER to flip
        // TestingMode.KEEP_ALIVE_ON_LEAVE = false before publish.
        if (TestingMode.KEEP_ALIVE_ON_LEAVE) return
        unlocked?.lock()
        unlocked = null
        finishAndRemoveTask()
    }

    /**
     * Lock on onStop, NOT onPause — onPause fires during transient
     * occlusions (system permission dialogs, biometric prompts, the
     * SAF picker the encrypt/decrypt flow uses). Locking on onPause
     * would wipe the KEK during the SAF round-trip and the in-flight
     * encrypt/decrypt would fail mid-operation.
     */
    override fun onPause() {
        super.onPause()
        Diagnostics.log("backups.MainActivity", "onPause (inFlight=${BackupsVaultManager.isInTransientFlight})")
        DiagnosticsDump.snapshotState(this, "onPause")
    }

    override fun onStop() {
        super.onStop()
        val inFlight = BackupsVaultManager.isInTransientFlight
        val isCfg = isChangingConfigurations
        val keepAlive = TestingMode.KEEP_ALIVE_ON_LEAVE
        Diagnostics.log("backups.MainActivity",
            "onStop (inFlight=$inFlight, changingConfigs=$isCfg, keepAlive=$keepAlive, willLock=${!isCfg && !inFlight && !keepAlive})")
        DiagnosticsDump.snapshotState(this, "onStop")
        // Preserve the unlocked vault across:
        //   - deliberate transient round-trips (SAF picker, biometric prompt)
        //   - the testing phase (TestingMode.KEEP_ALIVE_ON_LEAVE — RELEASE-
        //     BLOCKER to flip false before publish)
        if (!isCfg && !inFlight && !keepAlive) {
            unlocked?.lock()
            unlocked = null
        }
    }

    override fun onResume() {
        super.onResume()
        val vaultFlight = BackupsVaultManager.isInTransientFlight
        val commonFlight = TransientFlight.isActive()
        Diagnostics.log("backups.MainActivity",
            "onResume (vaultFlight=$vaultFlight commonFlight=$commonFlight)")
        // Skip the hardFail re-check during a SAF picker round-trip. The
        // onCreate check is the authoritative gate; on-resume re-checks
        // can self-inflict a denial-of-service when a probe (Tamper or
        // SuiteAttestation) flaps during the foreground transition.
        // Same fix as antivirus's single-file-scan crash. We honor BOTH
        // the vault-level flight (existing — wraps every SAF launcher
        // in this app) and the common TransientFlight (for callers
        // that don't go through the vault layer).
        if (vaultFlight || commonFlight) return
        Tamper.invalidate()
        val tamperResult = Tamper.check(applicationContext)
        if (tamperResult.hardFail) {
            Diagnostics.error("backups.MainActivity", "Tamper.check hardFail on resume — finishing")
            finishAndRemoveTask()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Diagnostics.log("backups.MainActivity", "onDestroy")
        unlocked?.lock()
        unlocked = null
    }
}

private enum class Stage { Setup, Unlock, RestoreRecovery, Main, Encrypt, Decrypt, RestoreContent, LocalSnapshots, DeviceSnapshot, Diagnostics }

@Composable
private fun BackupsRoot(
    activity: FragmentActivity,
    unlockedRef: () -> UnlockedBackupsVault?,
    setUnlocked: (UnlockedBackupsVault?) -> Unit,
    onClose: () -> Unit,
    initialViewUri: Uri? = null,
) {
    val ctx = LocalContext.current
    // Pending file-manager hand-off URI (§13). Consumed once we reach Main:
    // we jump to Decrypt with it pre-filled, then clear it so Back returns to
    // the hub rather than re-triggering.
    var pendingViewUri by rememberSaveable { mutableStateOf(initialViewUri) }
    // Save the stage *as a String* across activity recreation. Earlier
    // attempt used `rememberSaveable { mutableStateOf(Stage.X) }` relying
    // on the enum's Serializable contract via Compose's AutoSaver — the
    // shipped APK contained the "cannot be saved" error message which
    // suggests AutoSaver was rejecting the enum at runtime. Round-tripping
    // via String is bulletproof.
    var stageName by rememberSaveable {
        mutableStateOf(if (BackupsVault.exists(ctx)) Stage.Unlock.name else Stage.Setup.name)
    }
    val stage = remember(stageName) { Stage.valueOf(stageName) }
    val setStage: (Stage) -> Unit = {
        Diagnostics.log("backups.Root", "stage transition: $stageName → ${it.name}")
        stageName = it.name
    }
    val backToMain: () -> Unit = { setStage(Stage.Main) }
    when (stage) {
        Stage.Setup -> {
            KeepAliveBackHandler("backups.Root.Setup")
            SetupScreen(activity = activity, onCreated = {
                setUnlocked(it); setStage(Stage.Main)
            }, onClose = onClose)
        }
        Stage.Unlock -> {
            KeepAliveBackHandler("backups.Root.Unlock")
            UnlockScreen(
                activity = activity,
                onUnlocked = { setUnlocked(it); setStage(Stage.Main) },
                onNeedRestore = { setStage(Stage.RestoreRecovery) },
                onClose = onClose,
            )
        }
        Stage.RestoreRecovery -> {
            KeepAliveBackHandler("backups.Root.RestoreRecovery")
            RestoreRecoveryScreen(
                activity = activity,
                onRestored = { setUnlocked(it); setStage(Stage.Main) },
                onClose = onClose,
            )
        }
        Stage.Main -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            // If we arrived via a file-manager `.usbe` hand-off, route into
            // Decrypt with it pre-filled (the user has now unlocked).
            if (pendingViewUri != null) {
                LaunchedEffect(Unit) { setStage(Stage.Decrypt) }
            }
            KeepAliveBackHandler("backups.Root.Main")
            MainScreen(
                vault = v,
                onEncrypt = { setStage(Stage.Encrypt) },
                onDecrypt = { setStage(Stage.Decrypt) },
                onRestoreContent = { setStage(Stage.RestoreContent) },
                onRestoreRecovery = { setStage(Stage.RestoreRecovery) },
                onLocalSnapshots = { setStage(Stage.LocalSnapshots) },
                onDeviceSnapshot = { setStage(Stage.DeviceSnapshot) },
                onLock = { v.lock(); setUnlocked(null); onClose() },
                onDiagnostics = { setStage(Stage.Diagnostics) },
            )
        }
        Stage.Encrypt -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToMain() }
            EncryptScreen(vault = v, onBack = backToMain)
        }
        Stage.Decrypt -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            val handoff = pendingViewUri
            // Consume the hand-off URI so returning to this screen later is a
            // normal empty Decrypt, and Back goes to the hub.
            LaunchedEffect(handoff) { if (handoff != null) pendingViewUri = null }
            BackHandler { backToMain() }
            DecryptScreen(vault = v, onBack = backToMain, initialInputUri = handoff)
        }
        Stage.RestoreContent -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToMain() }
            ContentStreamRestoreScreen(vault = v, onBack = backToMain)
        }
        Stage.LocalSnapshots -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToMain() }
            LocalSnapshotsScreen(vault = v, onBack = backToMain)
        }
        Stage.DeviceSnapshot -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToMain() }
            DeviceSnapshotConfigScreen(vault = v, onBack = backToMain)
        }
        Stage.Diagnostics -> {
            BackHandler { backToMain() }
            DiagnosticsScreen(onBack = backToMain)
        }
    }
}

private fun deviceUnsupportedReason(ctx: Context): String? {
    val km = ctx.getSystemService(android.app.KeyguardManager::class.java)
    if (km == null || !km.isDeviceSecure) {
        return "Device screen lock required.\n\nBackups binds the master key " +
            "to your device's PIN / pattern / biometric. Set up a screen lock in " +
            "system Settings, then come back."
    }
    val bm = BiometricManager.from(ctx)
    val canAuth = bm.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL,
    )
    if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
        return "BiometricPrompt unavailable (status $canAuth). Configure a strong " +
            "biometric or device credential in system Settings."
    }
    return null
}

@Composable
private fun SetupScreen(
    activity: FragmentActivity,
    onCreated: (UnlockedBackupsVault) -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var step by remember { mutableIntStateOf(0) }
    var error by remember { mutableStateOf<String?>(null) }
    val deviceIssue = remember { deviceUnsupportedReason(ctx) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("backups — first-time setup", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        if (deviceIssue != null) {
            WarningCard(deviceIssue)
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
            return@Column
        }
        when (step) {
            0 -> {
                Text(
                    "Backups self-generates a 256-bit master key, self-encrypts " +
                        "it under a hardware-backed Keystore key, and self-binds it to " +
                        "this device's screen lock. The master is never displayed and " +
                        "never typed during normal use — every encrypt/decrypt is gated " +
                        "by your device biometric or PIN.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                WarningCard(
                    "Recovery is a FILE, never a code you type. Backups seals a " +
                        "recovery kit inside the app automatically, so a fingerprint " +
                        "or screen-lock change re-binds silently with nothing to enter. " +
                        "For a lost/replaced phone, export a recovery file to somewhere " +
                        "safe (USB, cloud) — anyone who has that file can open your " +
                        "vault, so keep it safe.",
                )
                Button(onClick = { step = 1 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Self-generate vault")
                }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
            1 -> {
                Text("Authenticate with your device to bind the vault master key.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                error?.let { Text(it, style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error) }
                LaunchedEffect(Unit) {
                    runCatching {
                        val cipher = Crypto.deviceAuthCipherForEncrypt()
                        promptAuth(activity, "Bind backups to this device", cipher,
                            onSuccess = { authed ->
                                runCatching {
                                    val v = BackupsVault.create(ctx, authed)
                                    // SELF-SEAL the recovery kit at create — mint a
                                    // random recovery key the user never sees, seal
                                    // the KEK material under the non-auth wrap key.
                                    // Nothing shown, nothing typed. A later
                                    // re-enrollment re-binds silently from this kit.
                                    val kek = v.kekBytes()
                                    try {
                                        RecoveryFile.seal(ctx, ctx.packageName, kek)
                                    } finally {
                                        Crypto.wipe(kek)
                                    }
                                    if (activity.lifecycle.currentState
                                            .isAtLeast(Lifecycle.State.STARTED)
                                    ) onCreated(v) else v.lock()
                                }.onFailure { error = "Setup failed: ${it.message}" }
                            },
                            onError = { msg -> error = "Authentication failed: $msg" },
                            onCancel = { error = "Authentication cancelled."; step = 0 },
                        )
                    }.onFailure { error = "Crypto init failed: ${it.message}" }
                }
            }
        }
    }
}

@Composable
private fun UnlockScreen(
    activity: FragmentActivity,
    onUnlocked: (UnlockedBackupsVault) -> Unit,
    onNeedRestore: () -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    // Reliable pre-prompt classification (backups.md §8.2): if the header is
    // on disk but the device-auth wrap key is gone, biometric re-enrollment or
    // a lock-screen change destroyed it — route to the silent re-bind rather
    // than launching a doomed BiometricPrompt that ends in a generic error.
    val keyState = remember {
        com.understory.security.VaultRecovery.keyStateAtStartup(
            ctx, BackupsVault.exists(ctx),
        )
    }
    // A doomed BiometricPrompt during daily unlock can also surface invalidation
    // late (classifyUnlockFailure); flipping this drives the same silent-rebind
    // LaunchedEffect below rather than duplicating the flow.
    var lateInvalidated by remember { mutableStateOf(false) }
    val invalidated = lateInvalidated || keyState ==
        com.understory.security.VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED

    // Silent re-bind (operator directive — nothing on screen, nothing typed):
    // on an invalidated vault, FIRST try the in-vault sealed recovery kit. It is
    // wrapped by the non-auth RecoveryWrapKey, which survives re-enrollment, so
    // we can rebuild the KEK and re-wrap it under a fresh device-auth key with a
    // single biometric confirmation and NO key entry. Only if the kit is gone
    // (returns null) do we fall back to importing an exported recovery file.
    var rebinding by remember { mutableStateOf(false) }
    LaunchedEffect(invalidated) {
        if (!invalidated || rebinding) return@LaunchedEffect
        val kek = RecoveryFile.readKekFromSealedKit(ctx)
        if (kek == null) {
            // No sealed kit — the only path left is the exported file.
            onNeedRestore()
            return@LaunchedEffect
        }
        rebinding = true
        runCatching {
            // Clear the invalidated alias so a fresh device-auth key is minted.
            Crypto.deleteDeviceAuthKey()
            val cipher = Crypto.deviceAuthCipherForEncrypt()
            promptAuth(activity, "Re-bind backups to this device", cipher,
                onSuccess = { authed ->
                    runCatching {
                        val v = BackupsVault.rebindFromKek(ctx, kek, authed)
                        // Re-seal the kit with a fresh recovery key now the vault
                        // is re-bound, so the at-rest kit stays valid.
                        val fresh = v.kekBytes()
                        try {
                            RecoveryFile.reseal(ctx, ctx.packageName, fresh)
                        } finally {
                            Crypto.wipe(fresh)
                        }
                        Crypto.wipe(kek)
                        if (activity.lifecycle.currentState
                                .isAtLeast(Lifecycle.State.STARTED)
                        ) onUnlocked(v) else v.lock()
                    }.onFailure {
                        Crypto.wipe(kek)
                        rebinding = false
                        error = "Silent re-bind failed. Restore from your recovery file instead."
                    }
                },
                onError = { msg ->
                    Crypto.wipe(kek)
                    rebinding = false
                    error = "Authentication failed: $msg"
                },
                onCancel = {
                    Crypto.wipe(kek)
                    rebinding = false
                    error = "Authentication cancelled."
                },
            )
        }.onFailure {
            Crypto.wipe(kek)
            rebinding = false
            error = "Re-bind init failed: ${it.message}"
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("backups — unlock", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)

        if (invalidated) {
            WarningCard(
                com.understory.security.RecoveryCopy.INVALIDATED_TITLE + ".\n\n" +
                    "Your biometric enrollment or screen lock changed, which reset " +
                    "this device's wrap key. Your backups are NOT lost — the app is " +
                    "silently re-binding the vault from its sealed recovery kit; " +
                    "just confirm with your device biometric or PIN.",
            )
            error?.let { Text(it, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error) }
            if (error != null) {
                // Silent re-bind couldn't complete — offer the file import path.
                Button(onClick = onNeedRestore, modifier = Modifier.fillMaxWidth()) {
                    Text("Restore from your recovery file")
                }
            } else {
                Text("Re-binding…", style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
            return@Column
        }

        Text("Authenticate with your device biometric or PIN.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        error?.let { Text(it, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error) }

        Button(
            onClick = {
                if (working) return@Button
                working = true; error = null
                runCatching {
                    val iv = BackupsVault.ivForUnlock(ctx)
                    val cipher = Crypto.deviceAuthCipherForDecrypt(iv)
                    promptAuth(activity, "Unlock backups vault", cipher,
                        onSuccess = { authed ->
                            runCatching {
                                val v = BackupsVault.unlock(ctx, authed)
                                if (activity.lifecycle.currentState
                                        .isAtLeast(Lifecycle.State.STARTED)
                                ) onUnlocked(v) else { v.lock(); working = false }
                            }.onFailure { t ->
                                working = false
                                // Distinguish invalidation (drive silent re-bind)
                                // from a transient failure (retry) — §8.2.
                                if (com.understory.security.VaultRecovery
                                        .classifyUnlockFailure(t) ==
                                    com.understory.security.VaultRecovery
                                        .VaultKeyState.PERMANENTLY_INVALIDATED
                                ) lateInvalidated = true
                                else error = "Vault decryption failed."
                            }
                        },
                        onError = { msg -> error = "Authentication failed: $msg"; working = false },
                        onCancel = { error = "Authentication cancelled."; working = false },
                    )
                }.onFailure { t ->
                    working = false
                    if (com.understory.security.VaultRecovery
                            .classifyUnlockFailure(t) ==
                        com.understory.security.VaultRecovery
                            .VaultKeyState.PERMANENTLY_INVALIDATED
                    ) lateInvalidated = true
                    else error = "Crypto init failed: ${t.message}"
                }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Authenticating…" else "Unlock with device auth")
        }
        OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
    }
}

/**
 * Restore-from-recovery-FILE flow (operator directive 2026-07-03 — "the screen
 * is the enemy"). Shown when the device-auth wrap key was destroyed AND the
 * in-vault sealed kit is gone (or the user chose to restore from an off-device
 * file). The user IMPORTS an opaque recovery file via SAF — they never type a
 * key. [RecoveryFile.importKit] reads the KEK material carried inside the file;
 * we then mint a FRESH device-auth wrap key (biometric-gated), re-wrap that KEK,
 * and re-seal a new in-vault kit. Every envelope stays decryptable.
 */
@Composable
private fun RestoreRecoveryScreen(
    activity: FragmentActivity,
    onRestored: (UnlockedBackupsVault) -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    val pickKit = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        BackupsVaultManager.endTransientFlight()
        if (uri == null) return@rememberLauncherForActivityResult
        if (working) return@rememberLauncherForActivityResult
        working = true; error = null
        // Read the KEK material out of the opaque recovery file — no typing.
        val kek = runCatching {
            ctx.contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "couldn't open the recovery file" }
                RecoveryFile.importKit(input)
            }
        }.getOrElse {
            working = false
            error = "That file isn't a valid backups recovery file, or it's " +
                "corrupt. (${it.message})"
            return@rememberLauncherForActivityResult
        }
        runCatching {
            // Clear the invalidated alias so a fresh device-auth key is minted.
            Crypto.deleteDeviceAuthKey()
            val cipher = Crypto.deviceAuthCipherForEncrypt()
            promptAuth(activity, "Re-bind backups to this device", cipher,
                onSuccess = { authed ->
                    runCatching {
                        val v = BackupsVault.rebindFromKek(ctx, kek, authed)
                        // Seal a fresh in-vault kit so silent re-bind works again.
                        val fresh = v.kekBytes()
                        try {
                            RecoveryFile.reseal(ctx, ctx.packageName, fresh)
                        } finally {
                            Crypto.wipe(fresh)
                        }
                        Crypto.wipe(kek)
                        if (activity.lifecycle.currentState
                                .isAtLeast(Lifecycle.State.STARTED)
                        ) onRestored(v) else { v.lock(); working = false }
                    }.onFailure {
                        Crypto.wipe(kek)
                        error = "Restore failed — the recovery file didn't match " +
                            "this vault, or the header is corrupt. (${it.message})"
                        working = false
                    }
                },
                onError = { msg ->
                    Crypto.wipe(kek)
                    error = "Authentication failed: $msg"; working = false
                },
                onCancel = {
                    Crypto.wipe(kek)
                    error = "Authentication cancelled."; working = false
                },
            )
        }.onFailure {
            Crypto.wipe(kek)
            error = "Crypto init failed: ${it.message}"; working = false
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("restore from recovery file", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        Text(
            "Pick the recovery file you exported (the .ukit file you saved to a " +
                "USB drive, cloud, or safe place). Backups reads it and re-binds " +
                "this vault — you never type a key. Nothing you backed up is lost.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        error?.let { Text(it, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error) }

        Button(
            onClick = {
                if (working) return@Button
                BackupsVaultManager.beginTransientFlight()
                runCatching { pickKit.launch(arrayOf("*/*")) }
                    .onFailure {
                        BackupsVaultManager.endTransientFlight()
                        error = "Couldn't open the file picker: ${it.message}"
                    }
            },
            enabled = !working,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Restoring…" else "Pick recovery file")
        }
        OutlinedButton(
            onClick = onClose,
            modifier = Modifier.fillMaxWidth(),
        ) { Text("Close") }
    }
}

private fun promptAuth(
    activity: FragmentActivity,
    title: String,
    cipher: Cipher,
    onSuccess: (Cipher) -> Unit,
    onError: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val executor = ContextCompat.getMainExecutor(activity)
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            val c = result.cryptoObject?.cipher
            if (c == null) onError("no cipher") else onSuccess(c)
        }
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            if (errorCode in setOf(
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED,
                )) onCancel() else onError(errString.toString())
        }
    }
    val prompt = BiometricPrompt(activity, executor, callback)
    val info = BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle("backups")
        .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        )
        .build()
    prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
}

/** The three top-level sections of the dashboard NavigationBar. */
private enum class HomeTab(val label: String, val icon: ImageVector) {
    Backup("Backup", Icons.Filled.Backup),
    Snapshots("Snapshots", Icons.Filled.History),
    Restore("Restore", Icons.Filled.Restore),
}

@Composable
private fun MainScreen(
    vault: UnlockedBackupsVault,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onRestoreContent: () -> Unit,
    onRestoreRecovery: () -> Unit,
    onLocalSnapshots: () -> Unit,
    onDeviceSnapshot: () -> Unit,
    onLock: () -> Unit,
    onDiagnostics: () -> Unit,
) {
    val ctx = LocalContext.current
    // Dev/diagnostics surface ships ONLY in eng builds. In prod BuildConfig.FLAVOR
    // is "prod", so the top-bar action, the eng-only footer, and every path into
    // DiagnosticsScreen are absent — a clean shipping face.
    val isEng = BuildConfig.FLAVOR == "eng"

    var tab by rememberSaveable { mutableStateOf(HomeTab.Backup.name) }
    val current = remember(tab) { HomeTab.valueOf(tab) }

    // "Export recovery file" (operator directive): write ONE opaque, self-
    // contained recovery file to a user-chosen SAF location. The file carries
    // its own recovery key plus the R-encrypted KEK material, so it restores on
    // a brand-new device. Its contents are NEVER displayed. Honest copy below.
    var exportStatus by remember { mutableStateOf<String?>(null) }
    val exportRecovery = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        BackupsVaultManager.endTransientFlight()
        if (uri == null) return@rememberLauncherForActivityResult
        val kek = vault.kekBytes()
        exportStatus = runCatching {
            ctx.contentResolver.openOutputStream(uri, "w").use { out ->
                requireNotNull(out) { "no output stream" }
                RecoveryFile.exportKit(ctx, out, kek)
            }
            "Recovery file written. Keep it safe — anyone who has it can open your vault."
        }.getOrElse { "Couldn't write the recovery file: ${it.message}" }
        Crypto.wipe(kek)
    }
    val onExportRecovery: () -> Unit = {
        exportStatus = null
        BackupsVaultManager.beginTransientFlight()
        runCatching {
            exportRecovery.launch("${ctx.packageName}-recovery.ukit")
        }.onFailure {
            BackupsVaultManager.endTransientFlight()
            exportStatus = "Couldn't open the save dialog: ${it.message}"
        }
    }

    // Newest few local snapshots, read fresh on each entry into Main. The store
    // is private to filesDir so this is a cheap header parse, not IO the user
    // waits on. Used by both the Backup summary and the Snapshots tab preview.
    val snapshots = remember { runCatching { LocalSnapshotStore.list(ctx) }.getOrDefault(emptyList()) }

    SuiteScaffold(
        title = androidx.compose.ui.res.stringResource(R.string.app_name),
        // Diagnostics is an ENG-ONLY affordance. Gated so the shipping (prod)
        // top bar carries no dev entry point.
        actions = {
            if (isEng) {
                IconButton(onClick = onDiagnostics) {
                    Icon(
                        imageVector = Icons.Filled.BugReport,
                        contentDescription = "Diagnostics (eng)",
                    )
                }
            }
        },
        // The suite status strip reads as a dev/debug smoke-test bar, so it ships
        // in eng only; prod gets a clean chrome with the NavigationBar as the
        // sole bottom surface.
        showSuiteFooter = isEng,
    ) { pad ->
        Column(modifier = Modifier.fillMaxSize().padding(pad)) {
            // Tab content fills the space above the NavigationBar; the FAB
            // overlays it on the Backup tab.
            Box(modifier = Modifier.fillMaxWidth().weight(1f)) {
                when (current) {
                    HomeTab.Backup -> BackupTab(
                        snapshotCount = snapshots.size,
                        onEncrypt = onEncrypt,
                        onDeviceSnapshot = onDeviceSnapshot,
                        onViewSnapshots = { tab = HomeTab.Snapshots.name },
                        onExportRecovery = onExportRecovery,
                        exportStatus = exportStatus,
                        onLock = onLock,
                    )
                    HomeTab.Snapshots -> SnapshotsTab(
                        snapshots = snapshots,
                        onManage = onLocalSnapshots,
                        onCreate = { tab = HomeTab.Backup.name },
                    )
                    HomeTab.Restore -> RestoreTab(
                        onDecrypt = onDecrypt,
                        onRestoreRecovery = onRestoreRecovery,
                        onRestoreContent = onRestoreContent,
                    )
                }

                // Primary create action, on the Backup tab where a "make a
                // backup" FAB is the natural primary action.
                if (current == HomeTab.Backup) {
                    ExtendedFloatingActionButton(
                        onClick = onEncrypt,
                        icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                        text = { Text("Back up now") },
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .padding(UnderstoryTheme.spacing.lg),
                    )
                }
            }

            HomeNavBar(current = current, onSelect = { tab = it.name })
        }
    }
}

/**
 * Dashboard bottom navigation. Kept as a separate composable so [MainScreen]'s
 * SuiteScaffold owns the top bar / eng footer and this owns the three top-level
 * section switch. Rendered at the bottom of [MainScreen]'s content column.
 */
@Composable
private fun HomeNavBar(current: HomeTab, onSelect: (HomeTab) -> Unit) {
    NavigationBar(
        containerColor = MaterialTheme.colorScheme.surface,
        contentColor = MaterialTheme.colorScheme.onSurface,
    ) {
        HomeTab.entries.forEach { t ->
            NavigationBarItem(
                selected = current == t,
                onClick = { onSelect(t) },
                icon = { Icon(t.icon, contentDescription = null) },
                label = { Text(t.label) },
            )
        }
    }
}

/**
 * Backup tab — the primary face: encryption-posture hero, snapshot summary,
 * the two backup destinations (single-file envelope + device-wide snapshot),
 * the export-recovery-file / lock controls, and honest complement copy.
 */
@Composable
private fun BackupTab(
    snapshotCount: Int,
    onEncrypt: () -> Unit,
    onDeviceSnapshot: () -> Unit,
    onViewSnapshots: () -> Unit,
    onExportRecovery: () -> Unit,
    exportStatus: String?,
    onLock: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(
                start = UnderstoryTheme.spacing.lg,
                end = UnderstoryTheme.spacing.lg,
                top = UnderstoryTheme.spacing.md,
                // Leave room so the FAB never covers the last card.
                bottom = UnderstoryTheme.spacing.xxl + UnderstoryTheme.spacing.xxl,
            ),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
    ) {
        // Posture hero — a shield-led card that states what protects the data,
        // in plain language, without overclaiming.
        SuiteCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Shield,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp),
                )
                Spacer(Modifier.width(UnderstoryTheme.spacing.md))
                Column {
                    Text(
                        "Encrypted, on this device",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        "AES-256-GCM · Argon2id · Keystore-bound master key",
                        style = MaterialTheme.typography.bodySmall,
                        color = UnderstoryTheme.semantic.dim,
                    )
                }
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                "The master key is self-generated and never typed during normal " +
                    "use — every backup is gated by your device biometric or PIN. " +
                    "Files stay local unless you move them off yourself.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SuiteSectionHeader("Back up")
        DashRow(
            icon = Icons.Filled.FolderZip,
            headline = "Back up a file",
            supporting = "Encrypt one file into a portable .usbe envelope (max 16 MiB).",
            onClick = onEncrypt,
        )
        DashRow(
            icon = Icons.Filled.PhoneAndroid,
            headline = "Device-wide snapshot",
            supporting = "Capture settings and standard user directories, encrypted.",
            onClick = onDeviceSnapshot,
        )
        DashRow(
            icon = Icons.Filled.History,
            headline = "Snapshots on this device",
            supporting = if (snapshotCount == 0) "None yet — your first backup will appear here."
                else "$snapshotCount saved locally.",
            onClick = onViewSnapshots,
            trailingCount = if (snapshotCount > 0) snapshotCount else null,
        )

        SuiteSectionHeader("Recovery")
        // Export writes ONE opaque recovery file to a SAF location. The file is
        // never displayed and the recovery key is never shown or typed — the app
        // self-manages it. SecureOutlinedButton keeps the tap-jacking guard on
        // this sensitive action.
        Text(
            "Your vault silently re-binds itself after a fingerprint or screen-lock " +
                "change — nothing to do. For a lost or replaced phone, export a " +
                "recovery file and keep it somewhere safe. It is a single opaque " +
                "file; anyone who has it can open your vault.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        SecureOutlinedButton(onClick = onExportRecovery, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.FileDownload, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            Text("Export recovery file")
        }
        exportStatus?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (it.startsWith("Recovery file written"))
                    UnderstoryTheme.semantic.success else UnderstoryTheme.semantic.warning,
            )
        }

        // Complement surfacing (§13, D-16/E) — honest facts about what this tool
        // does NOT do, and how to pair it with other tools.
        SuiteCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.CloudOff,
                    contentDescription = null,
                    tint = UnderstoryTheme.semantic.dim,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                Text(
                    "Excluded from Google One & Smart Switch",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
            }
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Text(
                "Your exported recovery file is the only off-device restore path — " +
                    "keep it safe and off this device.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Filled.Usb,
                    contentDescription = null,
                    tint = UnderstoryTheme.semantic.dim,
                    modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                Text(
                    "Off-device copies: point a snapshot destination at a " +
                        "Syncthing-synced folder or a USB-OTG drive. Backups only " +
                        "writes the encrypted file — the external tool handles " +
                        "replication. This app has no network permission.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        OutlinedButton(onClick = onLock, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            Text("Lock + close")
        }
    }
}

/**
 * Snapshots tab — a live count, a preview list of the newest local snapshots as
 * [SuiteListRow]s (label · timestamp · size, with a leading archive icon), and a
 * button into the full manage screen (restore / delete / retention). Empty state
 * when nothing has been saved yet.
 */
@Composable
private fun SnapshotsTab(
    snapshots: List<LocalSnapshotStore.Info>,
    onManage: () -> Unit,
    onCreate: () -> Unit,
) {
    if (snapshots.isEmpty()) {
        com.understory.security.ui.components.EmptyState(
            title = "No snapshots yet",
            body = "Encrypted backups you save to this device appear here. Make " +
                "your first from the Backup tab.",
            icon = Icons.Filled.History,
            action = {
                Button(onClick = onCreate) {
                    Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
                    Text("Make a backup")
                }
            },
        )
        return
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(
                start = UnderstoryTheme.spacing.lg,
                end = UnderstoryTheme.spacing.lg,
                top = UnderstoryTheme.spacing.md,
                bottom = UnderstoryTheme.spacing.xl,
            ),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.xs),
    ) {
        SuiteSectionHeader(
            "${snapshots.size} snapshot${if (snapshots.size == 1) "" else "s"} on this device",
        )
        // Preview the newest handful inline; the full manage screen owns restore,
        // delete, and retention (all behavior preserved there).
        snapshots.take(6).forEach { info ->
            SuiteListRow(
                headline = info.userLabel.ifEmpty { "(no label)" },
                supporting = "${info.appLabel} · ${info.formattedTimestamp()} · " +
                    "${info.sizeBytes / 1024} KiB",
                leading = {
                    Icon(
                        imageVector = Icons.Filled.FolderZip,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                    )
                },
            )
        }
        Spacer(Modifier.height(UnderstoryTheme.spacing.sm))
        Button(onClick = onManage, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.History, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            Text("Manage, restore & retention")
        }
    }
}

/**
 * Restore tab — the three restore paths as leading-icon dashboard rows: decrypt
 * an envelope on this device, re-bind this vault from an exported recovery file,
 * or restore a content-stream (.usbs) into a folder.
 */
@Composable
private fun RestoreTab(
    onDecrypt: () -> Unit,
    onRestoreRecovery: () -> Unit,
    onRestoreContent: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(
                start = UnderstoryTheme.spacing.lg,
                end = UnderstoryTheme.spacing.lg,
                top = UnderstoryTheme.spacing.md,
                bottom = UnderstoryTheme.spacing.xl,
            ),
        verticalArrangement = Arrangement.spacedBy(UnderstoryTheme.spacing.md),
    ) {
        SuiteCard {
            Text(
                "Restore a backup",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(UnderstoryTheme.spacing.xs))
            Text(
                "Decrypt an envelope you made on this device, or re-bind this vault " +
                    "from a recovery file you exported. Output is written to a " +
                    "location you pick.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        DashRow(
            icon = Icons.Filled.LockOpen,
            headline = "Decrypt an envelope",
            supporting = "This device's unlocked master key. For .usbe made here.",
            onClick = onDecrypt,
        )
        DashRow(
            icon = Icons.Filled.FileUpload,
            headline = "Restore from recovery file",
            supporting = "Import the .ukit file you exported — re-binds this vault. No typing.",
            onClick = onRestoreRecovery,
        )
        DashRow(
            icon = Icons.Filled.Devices,
            headline = "Restore a content stream",
            supporting = "Unpack a device-snapshot .usbs back into a folder you pick.",
            onClick = onRestoreContent,
        )
    }
}

/**
 * One dashboard entry: a [SuiteListRow] with a leading tinted icon, a supporting
 * line, a trailing chevron (or an optional count pill), and the whole row is the
 * tap target. Reuses the shared row so the tap-jacking guard + 56dp target +
 * merged a11y node all come for free.
 */
@Composable
private fun DashRow(
    icon: ImageVector,
    headline: String,
    supporting: String,
    onClick: () -> Unit,
    trailingCount: Int? = null,
) {
    SuiteListRow(
        headline = headline,
        supporting = supporting,
        onClick = onClick,
        leading = {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
        },
        trailing = {
            if (trailingCount != null) {
                Text(
                    trailingCount.toString(),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            } else {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.ArrowForward,
                    contentDescription = null,
                    tint = UnderstoryTheme.semantic.dim,
                )
            }
        },
    )
}

@Composable
private fun EncryptScreen(vault: UnlockedBackupsVault, onBack: () -> Unit) {
    val ctx = LocalContext.current
    // Picked URIs are rememberSaveable — Uri is Parcelable. Survives
    // activity recreation during SAF round-trip on Samsung.
    var inputUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var outputUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var label by rememberSaveable { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    // Pre-flight size of the picked input (§11, D-18): the single-shot
    // envelope caps input at 16 MiB (BackupsFlow.MAX_INPUT_SIZE). Surface it
    // BEFORE a failed encrypt by disabling Encrypt with a reason when over.
    var inputSize by rememberSaveable { mutableStateOf(-1L) }
    val overCap = inputSize in 0 until Long.MAX_VALUE && inputSize > BackupsFlow.MAX_INPUT_SIZE

    val pickInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        Diagnostics.log("backups.Encrypt", "pickInput result: uri=${if (uri != null) "non-null" else "null"}")
        BackupsVaultManager.endTransientFlight()
        inputUri = uri
        inputSize = if (uri == null) -1L else runCatching {
            androidx.documentfile.provider.DocumentFile.fromSingleUri(ctx, uri)?.length() ?: -1L
        }.getOrDefault(-1L)
    }
    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        Diagnostics.log("backups.Encrypt", "createOutput result: uri=${if (uri != null) "non-null" else "null"}")
        BackupsVaultManager.endTransientFlight()
        outputUri = uri
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("encrypt → envelope", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        Text(
            "Master key is unlocked — no passphrase to type. Envelope will be " +
                "decryptable on this device (biometric), or on another device " +
                "after you re-bind this vault there from your exported recovery file.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // SAF picker launchers use plain OutlinedButton, NOT SecureOutlinedButton.
        // The tap-jacking guard rejects taps with FLAG_WINDOW_IS_PARTIALLY_OBSCURED,
        // which Samsung Edge Panel and various system overlays trigger,
        // causing the picker to silently never open. Tap-jacking a "Pick file"
        // button is non-destructive — it just opens the system SAF picker,
        // which has its own anti-overlay protections. Sensitive actions
        // (Export recovery file) keep the SecureOutlinedButton wrapper.
        OutlinedButton(
            onClick = {
                Diagnostics.log("backups.Encrypt", "Pick input file: tap")
                BackupsVaultManager.beginTransientFlight()
                runCatching { pickInput.launch(arrayOf("*/*")) }
                    .onFailure {
                        Diagnostics.error("backups.Encrypt",
                            "pickInput.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                        BackupsVaultManager.endTransientFlight()
                    }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (inputUri == null) "Pick input file" else "Input: ${inputUri?.lastPathSegment ?: "(picked)"}")
        }
        Text(
            "Single-file envelopes are capped at 16 MiB. Larger files belong " +
                "in the device-snapshot content stream (from the main screen).",
            style = MaterialTheme.typography.bodySmall,
            color = UnderstoryTheme.semantic.dim,
        )
        if (overCap) {
            Text(
                "This file is ${inputSize / (1024 * 1024)} MiB — over the 16 MiB " +
                    "envelope cap. Pick a smaller file, or use the device-snapshot " +
                    "content stream for large data.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }
        OutlinedTextField(
            value = label,
            onValueChange = { label = it },
            label = { Text("Label (description, stored in cleartext header)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(
            onClick = {
                Diagnostics.log("backups.Encrypt", "Pick output location: tap")
                BackupsVaultManager.beginTransientFlight()
                runCatching { createOutput.launch("backup-${System.currentTimeMillis()}.usbe") }
                    .onFailure {
                        Diagnostics.error("backups.Encrypt",
                            "createOutput.launch threw: ${it.javaClass.simpleName}: ${it.message}")
                        BackupsVaultManager.endTransientFlight()
                    }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (outputUri == null) "Pick output location" else "Output: ${outputUri?.lastPathSegment ?: "(picked)"}")
        }
        status?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (it.startsWith("Encrypted")) UnderstoryTheme.semantic.success
                    else UnderstoryTheme.semantic.warning,
            )
        }
        Spacer(Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val ip = inputUri; val op = outputUri
                    if (ip == null || op == null || working || overCap) return@Button
                    working = true
                    val keyChars = vault.recoveryChars()
                    val result = BackupsFlow.encryptToEnvelope(
                        ctx = ctx,
                        inputUri = ip,
                        outputUri = op,
                        appLabel = "com.understory.backups",
                        userLabel = label,
                        passphrase = keyChars,  // codec wipes after use
                    )
                    status = when (result) {
                        is BackupsFlow.Result.Success -> result.message
                        is BackupsFlow.Result.Failure -> result.message
                    }
                    Toast.makeText(ctx, status, Toast.LENGTH_LONG).show()
                    working = false
                },
                enabled = inputUri != null && outputUri != null && !working && !overCap,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) {
                Text(if (working) "Encrypting…" else "Encrypt")
            }
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) { Text("Back") }
        }

        // Alternate "save locally" path. Doesn't need outputUri — writes
        // the envelope into the app's private filesDir/snapshots/ where
        // it can be browsed via "Snapshots saved on this device" on the
        // main screen. Useful for recurring backups where re-picking a
        // SAF location every time is friction. The encryption pipeline
        // is identical; only the destination differs.
        Spacer(Modifier.height(4.dp))
        Button(
            onClick = {
                val ip = inputUri
                if (ip == null || working || overCap) return@Button
                working = true
                val outFile = LocalSnapshotStore.reserveNew(ctx, "backups")
                val keyChars = vault.recoveryChars()
                val result = BackupsFlow.encryptToLocalSnapshot(
                    ctx = ctx,
                    inputUri = ip,
                    outputFile = outFile,
                    appLabel = "com.understory.backups",
                    userLabel = label,
                    passphrase = keyChars,
                )
                status = when (result) {
                    is BackupsFlow.Result.Success -> {
                        // Apply the "keep last N" retention (D-15) after a
                        // successful local write.
                        LocalSnapshotStore.applyRetention(ctx)
                        result.message + " Browse from \"Snapshots saved on this device\"."
                    }
                    is BackupsFlow.Result.Failure -> result.message
                }
                Toast.makeText(ctx, status, Toast.LENGTH_LONG).show()
                working = false
            },
            enabled = inputUri != null && !working && !overCap,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Saving locally…" else "Encrypt → save snapshot on this device")
        }
    }
}

@Composable
private fun DecryptScreen(
    vault: UnlockedBackupsVault,
    onBack: () -> Unit,
    initialInputUri: Uri? = null,
) {
    val ctx = LocalContext.current
    var inputUri by rememberSaveable { mutableStateOf<Uri?>(initialInputUri) }
    var outputUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    val pickInput = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        BackupsVaultManager.endTransientFlight()
        inputUri = uri
    }
    val createOutput = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        BackupsVaultManager.endTransientFlight()
        outputUri = uri
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("decrypt envelope (this device)", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        Text(
            "Uses this device's master key (already unlocked). For envelopes " +
                "made on a DIFFERENT device, re-bind this vault from that device's " +
                "exported recovery file (Restore tab → \"Restore from recovery file\").",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        OutlinedButton(
            onClick = {
                BackupsVaultManager.beginTransientFlight()
                pickInput.launch(arrayOf("*/*"))
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (inputUri == null) "Pick envelope file" else "Envelope: ${inputUri?.lastPathSegment ?: "(picked)"}")
        }
        OutlinedButton(
            onClick = {
                BackupsVaultManager.beginTransientFlight()
                createOutput.launch("recovered-${System.currentTimeMillis()}.bin")
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (outputUri == null) "Pick output location" else "Output: ${outputUri?.lastPathSegment ?: "(picked)"}")
        }
        status?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (it.startsWith("Decrypted")) UnderstoryTheme.semantic.success
                    else UnderstoryTheme.semantic.warning,
            )
        }
        Spacer(Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val ip = inputUri; val op = outputUri
                    if (ip == null || op == null || working) return@Button
                    working = true
                    val keyChars = vault.recoveryChars()
                    val result = BackupsFlow.decryptFromEnvelope(ctx, ip, op, keyChars)
                    status = when (result) {
                        is BackupsFlow.Result.Success -> result.message
                        is BackupsFlow.Result.Failure -> result.message
                    }
                    Toast.makeText(ctx, status, Toast.LENGTH_LONG).show()
                    working = false
                },
                enabled = inputUri != null && outputUri != null && !working,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) {
                Text(if (working) "Decrypting…" else "Decrypt")
            }
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) { Text("Back") }
        }
    }
}

/**
 * Content-stream restore (backups.md §2.3 — closes the D-2 "no decoder exists"
 * blocker). Picks a `.usbs` UDCSv002 stream + a destination SAF tree, decrypts
 * it under the unlocked vault KEK, and writes every file back under the tree
 * with a path-traversal guard. Runs entirely off the main thread (§7): the
 * codec verifies each chunk's GCM tag before the unpacker emits the affected
 * file, so a tampered/truncated stream aborts cleanly.
 */
@Composable
private fun ContentStreamRestoreScreen(vault: UnlockedBackupsVault, onBack: () -> Unit) {
    val ctx = LocalContext.current
    var streamUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var destTreeUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var status by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    val pickStream = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        BackupsVaultManager.endTransientFlight()
        // Sniff so we can reject a non-.usbs file up front (honest feedback).
        if (uri != null) {
            val fmt = BackupsFlow.sniff(ctx, uri)
            if (fmt != BackupsFlow.InputFormat.CONTENT_STREAM) {
                status = "That file isn't a content stream (.usbs). Pick a " +
                    "device-snapshot content stream."
                streamUri = null
            } else {
                status = null
                streamUri = uri
            }
        } else streamUri = uri
    }
    val pickTree = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        BackupsVaultManager.endTransientFlight()
        if (uri != null) {
            runCatching {
                ctx.contentResolver.takePersistableUriPermission(
                    uri, android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            }
            destTreeUri = uri
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("restore content stream", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        Text(
            "Decrypts a device-snapshot content stream (.usbs) and writes every " +
                "file back into a folder you pick. Uses this device's unlocked " +
                "master key. Files are written under their original section " +
                "(Pictures/, Downloads/, …).",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedButton(
            onClick = {
                BackupsVaultManager.beginTransientFlight()
                runCatching { pickStream.launch(arrayOf("*/*")) }
                    .onFailure { BackupsVaultManager.endTransientFlight() }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (streamUri == null) "Pick .usbs stream" else "Stream: ${streamUri?.lastPathSegment ?: "(picked)"}")
        }
        OutlinedButton(
            onClick = {
                BackupsVaultManager.beginTransientFlight()
                runCatching { pickTree.launch(null) }
                    .onFailure { BackupsVaultManager.endTransientFlight() }
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (destTreeUri == null) "Pick destination folder" else "Destination: ${destTreeUri?.lastPathSegment ?: "(picked)"}")
        }
        status?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (it.startsWith("Restored")) UnderstoryTheme.semantic.success
                    else UnderstoryTheme.semantic.warning,
            )
        }
        Spacer(Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val s = streamUri; val d = destTreeUri
                    if (s == null || d == null || working) return@Button
                    working = true
                    status = "Restoring…"
                    val keyChars = vault.recoveryChars()
                    // Off-main (§7): pipe the streaming decrypt into the UDCS
                    // unpacker on a worker thread; post the report back.
                    Thread({
                        val report = runCatching {
                            runContentStreamRestore(ctx, s, d, keyChars)
                        }
                        val msg = report.getOrNull()?.let { r ->
                            "Restored ${r.written} file(s), skipped ${r.skipped}. " +
                                "${r.totalBytes / 1024} KiB written."
                        } ?: "Restore failed: ${report.exceptionOrNull()?.message ?: "unknown error"}. " +
                            "The stream may be corrupt, or the key is wrong."
                        ContextCompat.getMainExecutor(ctx).execute {
                            status = msg
                            working = false
                        }
                    }, "content-stream-restore").start()
                },
                enabled = streamUri != null && destTreeUri != null && !working,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) {
                Text(if (working) "Restoring…" else "Restore")
            }
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) { Text("Back") }
        }
    }
}

/**
 * Runs the streaming decrypt → UDCS unpack pipeline. Owns [keyChars]: decodes a
 * copy for the codec and wipes both. Piped so memory stays bounded regardless
 * of stream size (§7). Throws on codec/format failure so the caller reports it.
 */
private fun runContentStreamRestore(
    ctx: Context,
    streamUri: Uri,
    destTreeUri: Uri,
    keyChars: CharArray,
): UserDirsContentRestore.Report {
    val destTree = androidx.documentfile.provider.DocumentFile.fromTreeUri(ctx, destTreeUri)
        ?: throw java.io.IOException("destination folder not resolvable")
    val pipeIn = java.io.PipedInputStream(1 shl 16)
    val pipeOut = java.io.PipedOutputStream(pipeIn)
    var unpackReport: UserDirsContentRestore.Report? = null
    var unpackError: Throwable? = null
    // Reader thread runs the unpacker on the decrypted side of the pipe.
    val reader = Thread({
        try {
            unpackReport = UserDirsContentRestore.unpack(pipeIn, destTree) { doc ->
                ctx.contentResolver.openOutputStream(doc.uri, "w")
                    ?: throw java.io.IOException("couldn't open output for ${doc.name}")
            }
        } catch (t: Throwable) {
            unpackError = t
        } finally {
            runCatching { pipeIn.close() }
        }
    }, "udcs-unpack")
    reader.start()
    val keyCopy = keyChars.copyOf()
    try {
        ctx.contentResolver.openInputStream(streamUri).use { cin ->
            requireNotNull(cin) { "couldn't open .usbs input" }
            // The codec derives its own key and wipes THAT; the passphrase
            // copy is ours to wipe.
            com.understory.backup.StreamingAesGcmCodec.decrypt(cin, pipeOut, keyCopy)
        }
    } finally {
        runCatching { pipeOut.close() }
        com.understory.security.Crypto.wipe(keyCopy)
        com.understory.security.Crypto.wipe(keyChars)
    }
    reader.join()
    unpackError?.let { throw it }
    return unpackReport ?: throw java.io.IOException("unpack produced no report")
}

/**
 * A caution-tinted informational card (the suite's warning surface) — replaces
 * the ad-hoc `Box(background(0xFF3D2A00, RoundedCornerShape))` pattern with the
 * `warningContainer`/`warning` token pair.
 */
@Composable
private fun WarningCard(text: String) {
    com.understory.security.ui.components.SuiteCard {
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = UnderstoryTheme.semantic.warning,
        )
    }
}
