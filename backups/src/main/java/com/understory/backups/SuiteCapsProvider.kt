package com.understory.backups

import com.understory.security.BaseCapabilityProvider

/**
 * backups's capability beacon. Consumers translate
 * `(com.understory.backups, version=1)` into [SuiteCapability.BACKUP_ENVELOPE]
 * via their KNOWN_PEERS table — an app that can encrypt/decrypt suite envelopes
 * and accept a deposit, NOT the deferred cross-app orchestrator (which re-appears
 * at beacon v2 only once a peer ships the deposit responder).
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
