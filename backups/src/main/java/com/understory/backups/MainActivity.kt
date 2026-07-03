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
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.backups.BuildConfig
import com.understory.backups.R
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.TransientFlight
import com.understory.security.SecureButton
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

private enum class Stage { Setup, Unlock, Rebind, Main, Encrypt, Decrypt, DecryptRecovery, RestoreContent, Reveal, LocalSnapshots, DeviceSnapshot, Diagnostics }

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
                onNeedRebind = { setStage(Stage.Rebind) },
                onClose = onClose,
            )
        }
        Stage.Rebind -> {
            KeepAliveBackHandler("backups.Root.Rebind")
            RebindScreen(
                activity = activity,
                onRebound = { setUnlocked(it); setStage(Stage.Main) },
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
                onEncrypt = { setStage(Stage.Encrypt) },
                onDecrypt = { setStage(Stage.Decrypt) },
                onDecryptRecovery = { setStage(Stage.DecryptRecovery) },
                onRestoreContent = { setStage(Stage.RestoreContent) },
                onReveal = { setStage(Stage.Reveal) },
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
        Stage.DecryptRecovery -> {
            BackHandler { backToMain() }
            DecryptRecoveryScreen(onBack = backToMain)
        }
        Stage.RestoreContent -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToMain() }
            ContentStreamRestoreScreen(vault = v, onBack = backToMain)
        }
        Stage.Reveal -> {
            val v = unlockedRef() ?: return run { setStage(Stage.Unlock) }
            BackHandler { backToMain() }
            RevealScreen(vault = v, onBack = backToMain)
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
    // The vault created in step 1, held until the mandatory recovery-key
    // escrow (step 2, backups.md §8.1 / D-4) is confirmed. Setup does NOT
    // complete — onCreated is not called — until the user records the key.
    var createdVault by remember { mutableStateOf<UnlockedBackupsVault?>(null) }

    if (step == 2) {
        val v = createdVault
        if (v == null) { step = 1 } else {
            SetupRecoveryEscrowStep(
                vault = v,
                onConfirmed = { onCreated(v) },
            )
            return
        }
    }

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
                    "Cross-device decrypt: the master can be revealed (also " +
                        "biometric-gated) as a base64 recovery string. To decrypt " +
                        "an envelope on a DIFFERENT device, reveal the recovery " +
                        "key here, transfer the string to the other device, and " +
                        "use the \"Decrypt with recovery key\" option there. " +
                        "Treat the recovery string as ultimate secret — anyone " +
                        "with it can decrypt every envelope you've made.",
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
                                    if (activity.lifecycle.currentState
                                            .isAtLeast(Lifecycle.State.STARTED)
                                    ) {
                                        // Do NOT complete setup yet — route to
                                        // the mandatory recovery-key escrow step
                                        // (§8.1). onCreated fires only after the
                                        // user confirms they saved the key.
                                        createdVault = v
                                        step = 2
                                    } else v.lock()
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

/**
 * Mandatory recovery-key escrow (backups.md §8.1, resolves D-4). Setup does not
 * complete until the user records the base64 recovery key (the vault's KEK).
 * Adding a fingerprint later destroys the Keystore wrap key, after which this
 * string is the ONLY way to decrypt any envelope — so we force it in front of
 * the user before the app is usable. FLAG_SECURE is already set on the window,
 * so screenshots are blocked; copy + save-to-file are offered instead.
 *
 * Confirmation is a short "type the last 6 characters" check — cheap proof the
 * user actually looked at and captured the key, not a checkbox they can reflex-
 * tap past.
 */
@Composable
private fun SetupRecoveryEscrowStep(
    vault: UnlockedBackupsVault,
    onConfirmed: () -> Unit,
) {
    val ctx = LocalContext.current
    val recovery = remember { vault.recoveryChars() }
    DisposableEffectWipe(recovery)
    val recoveryStr = remember(recovery) { String(recovery) }
    val last6 = remember(recoveryStr) {
        if (recoveryStr.length >= 6) recoveryStr.takeLast(6) else recoveryStr
    }
    var typed by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }

    val saveToFile = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain"),
    ) { uri ->
        BackupsVaultManager.endTransientFlight()
        if (uri == null) return@rememberLauncherForActivityResult
        val ok = runCatching {
            ctx.contentResolver.openOutputStream(uri, "w").use { out ->
                requireNotNull(out) { "no output stream" }
                out.write(recoveryStr.toByteArray(Charsets.UTF_8))
            }
        }.isSuccess
        status = if (ok) "Recovery key saved to the chosen file."
        else "Couldn't write the recovery-key file."
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("save your recovery key", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        WarningCard(
            "This key is the ONLY way to recover your backups if you add a " +
                "fingerprint, change your screen lock, or lose this phone. " +
                "Adding a biometric destroys this device's wrap key — after " +
                "that, every envelope you made is decryptable only with this " +
                "string. Save it somewhere safe and OFF this device. We " +
                "cannot recover it for you.",
        )
        InfoCard {
            Text(recoveryStr, style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface)
        }
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SecureButton(
                onClick = {
                    com.understory.security.Clipboard.copySensitive(
                        context = ctx,
                        chars = recovery,
                        autoClearSeconds = 30,
                        label = "backups-recovery",
                    )
                    status = "Copied. Cleared from clipboard in 30s if not overwritten."
                },
                modifier = Modifier.weight(1f),
            ) { Text("Copy") }
            OutlinedButton(
                onClick = {
                    BackupsVaultManager.beginTransientFlight()
                    runCatching {
                        saveToFile.launch("backups-recovery-key.txt")
                    }.onFailure {
                        BackupsVaultManager.endTransientFlight()
                        status = "Couldn't open the save dialog: ${it.message}"
                    }
                },
                modifier = Modifier.weight(1f),
            ) { Text("Save to file") }
        }
        Text(
            "To confirm you saved it, type the LAST 6 characters of the key:",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = typed,
            onValueChange = { typed = it; status = null },
            label = { Text("Last 6 characters") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        status?.let {
            Text(
                it,
                style = MaterialTheme.typography.bodyMedium,
                color = if (it.startsWith("Copied") || it.startsWith("Recovery key saved"))
                    UnderstoryTheme.semantic.success else UnderstoryTheme.semantic.warning,
            )
        }
        Button(
            onClick = {
                if (typed.trim() == last6) {
                    onConfirmed()
                } else {
                    status = "That doesn't match the last 6 characters. Check the key above."
                }
            },
            enabled = typed.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("I saved it — finish setup")
        }
    }
}

@Composable
private fun UnlockScreen(
    activity: FragmentActivity,
    onUnlocked: (UnlockedBackupsVault) -> Unit,
    onNeedRebind: () -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }
    // Reliable pre-prompt classification (backups.md §8.2): if the header is
    // on disk but the device-auth wrap key is gone, biometric re-enrollment or
    // a lock-screen change destroyed it — route straight to re-bind rather than
    // launching a doomed BiometricPrompt that ends in a generic error.
    val keyState = remember {
        com.understory.security.VaultRecovery.keyStateAtStartup(
            ctx, BackupsVault.exists(ctx),
        )
    }
    val invalidated = keyState ==
        com.understory.security.VaultRecovery.VaultKeyState.PERMANENTLY_INVALIDATED

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("backups — unlock", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)

        if (invalidated) {
            WarningCard(
                com.understory.security.RecoveryCopy.INVALIDATED_TITLE + ".\n\n" +
                    "Your biometric enrollment or screen lock changed, which " +
                    "reset this device's wrap key. Your backups are NOT lost — " +
                    "re-bind this vault with the recovery key you saved at " +
                    "setup, and every envelope stays decryptable.",
            )
            Button(onClick = onNeedRebind, modifier = Modifier.fillMaxWidth()) {
                Text("Re-bind with recovery key")
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
                                // Distinguish invalidation (route to re-bind)
                                // from a transient failure (retry) — §8.2.
                                if (com.understory.security.VaultRecovery
                                        .classifyUnlockFailure(t) ==
                                    com.understory.security.VaultRecovery
                                        .VaultKeyState.PERMANENTLY_INVALIDATED
                                ) onNeedRebind()
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
                    ) onNeedRebind()
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
 * Re-bind flow (backups.md §8.2). Shown when the device-auth wrap key was
 * destroyed by biometric re-enrollment / lock change. The user pastes the
 * recovery key they saved at Setup; we mint a FRESH wrap key (biometric-gated)
 * and re-wrap the same KEK, so the vault — and every envelope — is usable again
 * on this device.
 */
@Composable
private fun RebindScreen(
    activity: FragmentActivity,
    onRebound: (UnlockedBackupsVault) -> Unit,
    onClose: () -> Unit,
) {
    val ctx = LocalContext.current
    var recoveryKey by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var working by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("re-bind this vault", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        Text(
            "Enter the base64 recovery key you saved at setup. We'll re-create " +
                "this device's wrap key (biometric) and re-establish the vault. " +
                "Nothing you backed up is lost.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        error?.let { Text(it, style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error) }

        OutlinedTextField(
            value = recoveryKey,
            onValueChange = { recoveryKey = it },
            label = { Text("Recovery key (base64)") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = {
                if (working || recoveryKey.isBlank()) return@Button
                working = true; error = null
                val keyChars = recoveryKey.toCharArray()
                recoveryKey = ""  // drop the live String reference
                runCatching {
                    // Clear the invalidated alias so a fresh key is generated.
                    Crypto.deleteDeviceAuthKey()
                    val cipher = Crypto.deviceAuthCipherForEncrypt()
                    promptAuth(activity, "Re-bind backups to this device", cipher,
                        onSuccess = { authed ->
                            runCatching {
                                val v = BackupsVault.rebindFromRecovery(ctx, keyChars, authed)
                                Crypto.wipe(keyChars)
                                if (activity.lifecycle.currentState
                                        .isAtLeast(Lifecycle.State.STARTED)
                                ) onRebound(v) else { v.lock(); working = false }
                            }.onFailure {
                                Crypto.wipe(keyChars)
                                error = "Re-bind failed — wrong recovery key or " +
                                    "a corrupted vault header. (${it.message})"
                                working = false
                            }
                        },
                        onError = { msg ->
                            Crypto.wipe(keyChars)
                            error = "Authentication failed: $msg"; working = false
                        },
                        onCancel = {
                            Crypto.wipe(keyChars)
                            error = "Authentication cancelled."; working = false
                        },
                    )
                }.onFailure {
                    Crypto.wipe(keyChars)
                    error = "Crypto init failed: ${it.message}"; working = false
                }
            },
            enabled = recoveryKey.isNotBlank() && !working,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (working) "Re-binding…" else "Re-bind vault")
        }
        OutlinedButton(
            onClick = { recoveryKey = ""; onClose() },
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
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onDecryptRecovery: () -> Unit,
    onRestoreContent: () -> Unit,
    onReveal: () -> Unit,
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
                        onReveal = onReveal,
                        onLock = onLock,
                    )
                    HomeTab.Snapshots -> SnapshotsTab(
                        snapshots = snapshots,
                        onManage = onLocalSnapshots,
                        onCreate = { tab = HomeTab.Backup.name },
                    )
                    HomeTab.Restore -> RestoreTab(
                        onDecrypt = onDecrypt,
                        onDecryptRecovery = onDecryptRecovery,
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
 * the reveal/lock controls, and honest complement copy.
 */
@Composable
private fun BackupTab(
    snapshotCount: Int,
    onEncrypt: () -> Unit,
    onDeviceSnapshot: () -> Unit,
    onViewSnapshots: () -> Unit,
    onReveal: () -> Unit,
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
        // Reveal directly exposes the master key — the one true tap-jacking-
        // sensitive entry point — so it keeps the SecureOutlinedButton wrapper.
        SecureOutlinedButton(onClick = onReveal, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(UnderstoryTheme.spacing.sm))
            Text("Reveal recovery key (for transfer)")
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
                "Your recovery key is the only restore path — keep it safe and off " +
                    "this device.",
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
 * an envelope on this device, decrypt with a cross-device recovery key, or
 * restore a content-stream (.usbs) into a folder.
 */
@Composable
private fun RestoreTab(
    onDecrypt: () -> Unit,
    onDecryptRecovery: () -> Unit,
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
                "Decrypt an envelope you made, or one from another device using its " +
                    "recovery key. Output is written to a location you pick.",
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
            icon = Icons.Filled.Key,
            headline = "Decrypt with recovery key",
            supporting = "Cross-device: paste the base64 recovery key from the origin.",
            onClick = onDecryptRecovery,
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
                "decryptable on this device (biometric) or any device with the " +
                "recovery key.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // SAF picker launchers use plain OutlinedButton, NOT SecureOutlinedButton.
        // The tap-jacking guard rejects taps with FLAG_WINDOW_IS_PARTIALLY_OBSCURED,
        // which Samsung Edge Panel and various system overlays trigger,
        // causing the picker to silently never open. Tap-jacking a "Pick file"
        // button is non-destructive — it just opens the system SAF picker,
        // which has its own anti-overlay protections. Destructive actions
        // (Encrypt, Decrypt, Lock, Reveal) keep the SecureButton wrapper.
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
                "made on a DIFFERENT device, use the \"Decrypt with recovery key\" " +
                "option from the main screen.",
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

@Composable
private fun DecryptRecoveryScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    var inputUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    var outputUri by rememberSaveable { mutableStateOf<Uri?>(null) }
    // recoveryKey deliberately NOT rememberSaveable — typed secret should
    // never persist into savedInstanceState (which gets written to disk).
    var recoveryKey by remember { mutableStateOf("") }
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
        Text("decrypt with recovery key", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        Text(
            "For envelopes made on a different device. Paste the base64 " +
                "recovery key from the origin device's Reveal screen.",
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
        OutlinedTextField(
            value = recoveryKey,
            onValueChange = { recoveryKey = it },
            label = { Text("Recovery key (base64 from origin device)") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
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
                    if (ip == null || op == null || recoveryKey.isEmpty() || working) return@Button
                    working = true
                    val keyChars = recoveryKey.toCharArray()
                    recoveryKey = ""  // drop the live String reference
                    val result = BackupsFlow.decryptFromEnvelope(ctx, ip, op, keyChars)
                    status = when (result) {
                        is BackupsFlow.Result.Success -> result.message
                        is BackupsFlow.Result.Failure -> result.message
                    }
                    Toast.makeText(ctx, status, Toast.LENGTH_LONG).show()
                    working = false
                },
                enabled = inputUri != null && outputUri != null && recoveryKey.isNotEmpty() && !working,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            ) {
                Text(if (working) "Decrypting…" else "Decrypt")
            }
            OutlinedButton(
                onClick = { recoveryKey = ""; onBack() },
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

@Composable
private fun RevealScreen(vault: UnlockedBackupsVault, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val recovery = remember { vault.recoveryChars() }
    DisposableEffectWipe(recovery)

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("recovery key", style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onSurface)
        WarningCard(
            "Treat this string as ultimate secret. Anyone with it can decrypt " +
                "every envelope you've made. Transfer to the destination device " +
                "via a trusted channel (paper, password manager, secure messenger). " +
                "FLAG_SECURE prevents screenshots; you'll need to type or paste it.",
        )
        InfoCard {
            Text(
                String(recovery),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
        Spacer(Modifier.height(8.dp))
        SecureButton(
            onClick = {
                // Real 30s clear via the shared Clipboard helper (backups.md
                // §8.3, A-8/D-12): it sets EXTRA_IS_SENSITIVE AND schedules a
                // Handler-backed clearPrimaryClip after 30s that fires ONLY if
                // our labeled+sensitive clip is still the primary clip (a
                // third-party overwrite isn't trampled). The old toast claimed
                // an auto-clear no code performed.
                com.understory.security.Clipboard.copySensitive(
                    context = ctx,
                    chars = recovery,
                    autoClearSeconds = 30,
                    label = "backups-recovery",
                )
                Toast.makeText(
                    ctx,
                    "Copied. Cleared from clipboard in 30s if not overwritten.",
                    Toast.LENGTH_LONG,
                ).show()
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Copy to clipboard (sensitive)")
        }
        OutlinedButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) { Text("Done") }
    }
}

/**
 * Wipe the displayed recovery CharArray when the Reveal composable
 * leaves composition. The vault's master KEK itself stays alive in
 * BackupsVaultManager; this is just the on-screen view buffer.
 */
@Composable
private fun DisposableEffectWipe(buf: CharArray) {
    androidx.compose.runtime.DisposableEffect(buf) {
        onDispose { com.understory.security.Crypto.wipe(buf) }
    }
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

/**
 * A neutral surfaceVariant card — replaces the ad-hoc `Box(background(0xFF1C1C1C
 * / 0xFF141414))` pattern for reference/complement copy and the revealed
 * recovery string.
 */
@Composable
private fun InfoCard(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    com.understory.security.ui.components.SuiteCard(content = content)
}
