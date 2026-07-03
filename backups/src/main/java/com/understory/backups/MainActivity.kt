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
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.understory.security.Crypto
import com.understory.security.Diagnostics
import com.understory.security.DiagnosticsDump
import com.understory.security.DiagnosticsScreen
import com.understory.security.KeepAliveBackHandler
import com.understory.security.TransientFlight
import com.understory.security.SecureButton
import com.understory.security.SecureOutlinedButton
import com.understory.security.SuiteStatusFooter
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
                Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
                    Column(modifier = Modifier.padding(20.dp)) {
                        Text("backups crash", color = Color(0xFFEF5350), fontSize = 18.sp)
                        Text(t.toString(), color = Color(0xFFE0E0E0), fontSize = 11.sp)
                    }
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
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0A0A)) {
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
        Text("backups — first-time setup", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        if (deviceIssue != null) {
            Box(modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                .padding(12.dp)) {
                Text(deviceIssue, color = Color(0xFFFFB74D), fontSize = 12.sp)
            }
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
                    color = Color(0xFF9E9E9E), fontSize = 12.sp,
                )
                Box(modifier = Modifier.fillMaxWidth()
                    .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                    .padding(12.dp)) {
                    Text(
                        "Cross-device decrypt: the master can be revealed (also " +
                            "biometric-gated) as a base64 recovery string. To decrypt " +
                            "an envelope on a DIFFERENT device, reveal the recovery " +
                            "key here, transfer the string to the other device, and " +
                            "use the \"Decrypt with recovery key\" option there. " +
                            "Treat the recovery string as ultimate secret — anyone " +
                            "with it can decrypt every envelope you've made.",
                        color = Color(0xFFFFB74D), fontSize = 11.sp,
                    )
                }
                Button(onClick = { step = 1 }, modifier = Modifier.fillMaxWidth()) {
                    Text("Self-generate vault")
                }
                OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
            1 -> {
                Text("Authenticate with your device to bind the vault master key.",
                    color = Color(0xFF9E9E9E), fontSize = 12.sp)
                error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }
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
        Text("save your recovery key", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Box(
            modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                .padding(12.dp),
        ) {
            Text(
                "This key is the ONLY way to recover your backups if you add a " +
                    "fingerprint, change your screen lock, or lose this phone. " +
                    "Adding a biometric destroys this device's wrap key — after " +
                    "that, every envelope you made is decryptable only with this " +
                    "string. Save it somewhere safe and OFF this device. We " +
                    "cannot recover it for you.",
                color = Color(0xFFFFB74D), fontSize = 12.sp,
            )
        }
        Box(
            modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                .padding(14.dp),
        ) {
            Text(recoveryStr, color = Color(0xFFE0E0E0), fontSize = 14.sp)
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
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
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
                color = if (it.startsWith("Copied") || it.startsWith("Recovery key saved"))
                    Color(0xFF81C784) else Color(0xFFFFB74D),
                fontSize = 12.sp,
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
        Text("backups — unlock", color = Color(0xFFE0E0E0), fontSize = 22.sp)

        if (invalidated) {
            Box(
                modifier = Modifier.fillMaxWidth()
                    .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                    .padding(12.dp),
            ) {
                Text(
                    com.understory.security.RecoveryCopy.INVALIDATED_TITLE + ".\n\n" +
                        "Your biometric enrollment or screen lock changed, which " +
                        "reset this device's wrap key. Your backups are NOT lost — " +
                        "re-bind this vault with the recovery key you saved at " +
                        "setup, and every envelope stays decryptable.",
                    color = Color(0xFFFFB74D), fontSize = 12.sp,
                )
            }
            Button(onClick = onNeedRebind, modifier = Modifier.fillMaxWidth()) {
                Text("Re-bind with recovery key")
            }
            OutlinedButton(onClick = onClose, modifier = Modifier.fillMaxWidth()) { Text("Close") }
            return@Column
        }

        Text("Authenticate with your device biometric or PIN.",
            color = Color(0xFF9E9E9E), fontSize = 13.sp)
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }

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
        Text("re-bind this vault", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Enter the base64 recovery key you saved at setup. We'll re-create " +
                "this device's wrap key (biometric) and re-establish the vault. " +
                "Nothing you backed up is lost.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
        )
        error?.let { Text(it, color = Color(0xFFEF5350), fontSize = 12.sp) }

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
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("backups", color = Color(0xFFE0E0E0), fontSize = 28.sp)
        Text(
            "Local-first encrypted-envelope tool. Master key is self-generated, " +
                "Keystore-bound, and never typed during normal use. AES-256-GCM " +
                "with Argon2id key derivation. Files stay on this device.",
            color = Color(0xFF9E9E9E), fontSize = 13.sp,
        )
        Spacer(Modifier.height(8.dp))
        // Per SAMSUNG_QUIRKS.md: navigation buttons are plain Button. The
        // destructive operations live on the next screen and are gated by
        // the codec which checks the unlocked KEK + picked URIs. Reveal
        // stays SecureOutlinedButton because it directly exposes the
        // master key — the only true tap-jacking-sensitive entry point.
        Button(onClick = onEncrypt, modifier = Modifier.fillMaxWidth()) {
            Text("Encrypt a file → envelope")
        }
        OutlinedButton(onClick = onDecrypt, modifier = Modifier.fillMaxWidth()) {
            Text("Decrypt an envelope (this device)")
        }
        OutlinedButton(onClick = onDecryptRecovery, modifier = Modifier.fillMaxWidth()) {
            Text("Decrypt with recovery key (cross-device)")
        }
        Spacer(Modifier.height(4.dp))
        OutlinedButton(onClick = onLocalSnapshots, modifier = Modifier.fillMaxWidth()) {
            Text("Snapshots saved on this device")
        }
        OutlinedButton(onClick = onDeviceSnapshot, modifier = Modifier.fillMaxWidth()) {
            Text("Device-wide snapshot (settings + user dirs)")
        }
        OutlinedButton(onClick = onRestoreContent, modifier = Modifier.fillMaxWidth()) {
            Text("Restore a content stream (.usbs → files)")
        }
        Spacer(Modifier.height(4.dp))
        SecureOutlinedButton(onClick = onReveal, modifier = Modifier.fillMaxWidth()) {
            Text("Reveal recovery key (for transfer)")
        }
        OutlinedButton(onClick = onLock, modifier = Modifier.fillMaxWidth()) {
            Text("Lock + close")
        }

        // Complement surfacing (§13, D-16/E) — three honest facts that used to
        // live only in config files or nowhere.
        Spacer(Modifier.height(8.dp))
        Box(
            modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF141414), RoundedCornerShape(6.dp))
                .padding(12.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "This vault is excluded from Google One and Smart Switch — " +
                        "your recovery key is the only restore path. Keep it safe " +
                        "and off this device.",
                    color = Color(0xFF9E9E9E), fontSize = 11.sp,
                )
                Text(
                    "Moving phones? Reveal your recovery key, transfer any " +
                        "snapshot to the new device, and use \"Decrypt with " +
                        "recovery key\" there.",
                    color = Color(0xFF9E9E9E), fontSize = 11.sp,
                )
                Text(
                    "Off-device backup: point your snapshot destination at a " +
                        "Syncthing-synced folder or a USB-OTG drive. Backups only " +
                        "writes the encrypted file — the external tool handles " +
                        "replication, with no network permission in this app.",
                    color = Color(0xFF9E9E9E), fontSize = 11.sp,
                )
            }
        }

        Spacer(Modifier.weight(1f))
        OutlinedButton(onClick = onDiagnostics, modifier = Modifier.fillMaxWidth()) {
            Text("Diagnostics")
        }
        SuiteStatusFooter()
    }
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
        Text("encrypt → envelope", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Master key is unlocked — no passphrase to type. Envelope will be " +
                "decryptable on this device (biometric) or any device with the " +
                "recovery key.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
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
            color = Color(0xFF707070), fontSize = 11.sp,
        )
        if (overCap) {
            Text(
                "This file is ${inputSize / (1024 * 1024)} MiB — over the 16 MiB " +
                    "envelope cap. Pick a smaller file, or use the device-snapshot " +
                    "content stream for large data.",
                color = Color(0xFFEF5350), fontSize = 12.sp,
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
                color = if (it.startsWith("Encrypted")) Color(0xFF81C784) else Color(0xFFFFB74D),
                fontSize = 12.sp,
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
        Text("decrypt envelope (this device)", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Uses this device's master key (already unlocked). For envelopes " +
                "made on a DIFFERENT device, use the \"Decrypt with recovery key\" " +
                "option from the main screen.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
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
                color = if (it.startsWith("Decrypted")) Color(0xFF81C784) else Color(0xFFFFB74D),
                fontSize = 12.sp,
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
        Text("decrypt with recovery key", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "For envelopes made on a different device. Paste the base64 " +
                "recovery key from the origin device's Reveal screen.",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
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
                color = if (it.startsWith("Decrypted")) Color(0xFF81C784) else Color(0xFFFFB74D),
                fontSize = 12.sp,
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
        Text("restore content stream", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Text(
            "Decrypts a device-snapshot content stream (.usbs) and writes every " +
                "file back into a folder you pick. Uses this device's unlocked " +
                "master key. Files are written under their original section " +
                "(Pictures/, Downloads/, …).",
            color = Color(0xFF9E9E9E), fontSize = 12.sp,
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
                color = if (it.startsWith("Restored")) Color(0xFF81C784) else Color(0xFFFFB74D),
                fontSize = 12.sp,
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
        Text("recovery key", color = Color(0xFFE0E0E0), fontSize = 22.sp)
        Box(
            modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF3D2A00), RoundedCornerShape(6.dp))
                .padding(12.dp),
        ) {
            Text(
                "Treat this string as ultimate secret. Anyone with it can decrypt " +
                    "every envelope you've made. Transfer to the destination device " +
                    "via a trusted channel (paper, password manager, secure messenger). " +
                    "FLAG_SECURE prevents screenshots; you'll need to type or paste it.",
                color = Color(0xFFFFB74D),
                fontSize = 12.sp,
            )
        }
        Box(
            modifier = Modifier.fillMaxWidth()
                .background(Color(0xFF1C1C1C), RoundedCornerShape(6.dp))
                .padding(14.dp),
        ) {
            Text(
                String(recovery),
                color = Color(0xFFE0E0E0),
                fontSize = 14.sp,
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
