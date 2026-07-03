package com.understory.backups

import com.understory.security.BaseCapabilityProvider

/**
 * backups's capability beacon. Consumers translate
 * `(com.understory.backups, version=1)` into [SuiteCapability.BACKUP_ORCHESTRATOR]
 * via their KNOWN_PEERS table.
 */
class SuiteCapsProvider : BaseCapabilityProvider() {
    override val providedVersion: Int = 1
}
