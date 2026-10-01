package org.miga.android

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.asCoroutineDispatcher
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.concurrent.Executors

class SettingsRepositoryTest {
    @Test fun nativeAvailabilitySelectsCombinedCaptureRegardlessOfSavedMode() = runBlocking {
        val store = MemorySettings()
        val repository = SettingsRepository(store, MemorySecrets()) { false }
        val profile = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        repository.assignPackage("org.example.app", profile.id)
        repository.saveIpv4Rule(null, profile.id, "9.9.9.0/24")
        repository.saveDomainRule(null, profile.id, "example.org")
        val public = repository.snapshot(setOf("org.example.app"), true)
        assertEquals(CaptureMode.PUBLIC_IPV4_RULES, public.captureMode)
        assertEquals(1, public.ipv4Rules.size)
        assertEquals(1, public.domainRules.size)
        val assigned = repository.snapshot(setOf("org.example.app"), false)
        assertEquals(CaptureMode.ASSIGNED_APPS, assigned.captureMode)
        assertTrue(assigned.ipv4Rules.isEmpty())
        assertTrue(assigned.domainRules.isEmpty())
        assertEquals(CaptureMode.ASSIGNED_APPS, repository.load().captureMode)
        store.value = SettingsCodec.encode(repository.load().copy(captureMode = CaptureMode.PUBLIC_IPV4_RULES))
        assertEquals(CaptureMode.ASSIGNED_APPS,
            repository.snapshot(setOf("org.example.app"), false).captureMode)
        assertEquals(CaptureMode.PUBLIC_IPV4_RULES,
            repository.snapshot(setOf("org.example.app"), true).captureMode)
    }

    @Test fun publicModeDoesNotRequireAssignedAppsButAssignedModeDoes() = runBlocking {
        val store = MemorySettings()
        val repository = SettingsRepository(store, MemorySecrets()) { false }
        val profile = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        repository.saveIpv4Rule(null, profile.id, "9.9.9.0/24")
        assertEquals(CaptureMode.PUBLIC_IPV4_RULES, repository.snapshot(emptySet(), true).captureMode)
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { repository.snapshot(emptySet(), false) }
        }
        Unit
    }

    @Test fun appOnlyRoutingExcludesUnassignedPackagesEvenWithNativeAndLegacyPublicMode() = runBlocking {
        val store = MemorySettings()
        val repository = SettingsRepository(store, MemorySecrets()) { false }
        val profile = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        repository.assignPackage("org.example.app", profile.id)
        store.value = SettingsCodec.encode(repository.load().copy(captureMode = CaptureMode.PUBLIC_IPV4_RULES))
        val session = repository.snapshot(setOf("org.example.app", "com.carshering"), true)
        assertEquals(CaptureMode.ASSIGNED_APPS, session.captureMode)
        assertEquals(setOf("org.example.app"), session.packages)
        assertEquals(profile.id, session.assignments["org.example.app"])
        assertTrue(session.ipv4Rules.isEmpty())
        assertTrue(session.domainRules.isEmpty())
    }

    @Test fun legacySelectionMigratesToStableProfileAndPreservesSecretRef() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val profile = repository.saveProfile(null, "Old", "8.8.8.8", "6000", "6000", keys).profiles.single()
        val raw = ByteArrayOutputStream()
        DataOutputStream(raw).use { out ->
            out.writeInt(1); out.writeInt(1)
            out.writeUTF(profile.id); out.writeUTF(profile.name); out.writeUTF(profile.address)
            out.writeInt(profile.firstPort); out.writeInt(profile.lastPort); out.writeUTF(profile.secretRef)
            out.writeBoolean(true); out.writeUTF(profile.id)
            out.writeInt(1); out.writeUTF("org.example.app")
        }
        settings.value = Base64.getEncoder().encodeToString(raw.toByteArray())
        val migrated = repository.load()
        assertEquals(4, migrated.schemaVersion)
        assertEquals(profile.id, migrated.assignments["org.example.app"])
        assertEquals(profile.id, migrated.dnsProfileId)
        assertEquals(profile.secretRef, migrated.profiles.single().secretRef)
        assertEquals(CaptureMode.ASSIGNED_APPS, migrated.captureMode)
        assertTrue(migrated.ipv4Rules.isEmpty())
        assertEquals(setOf(profile.id), repository.snapshot(setOf("org.example.app"), false).profiles.keys)
        assertThrows(IllegalArgumentException::class.java) { runBlocking { repository.deleteProfile(profile.id) } }
        assertEquals(profile.secretRef, repository.load().profiles.single().secretRef)
    }

    @Test fun sessionSnapshotDoesNotExposeMutableKeysOrAssignments() {
        val xor = ByteArray(128) { 7 }
        val swap = ByteArray(8) { 3 }
        val assignments = mutableMapOf("org.example.app" to "one")
        val session = SessionSettings(mapOf("one" to ServerSession("8.8.8.8", 0x08080808,
            6000, 6000, xor, swap)), assignments, "one")
        xor[0] = 0; swap[0] = 0; assignments.clear()
        session.profiles.getValue("one").xorKey[0] = 0
        assertEquals(7, session.profiles.getValue("one").xorKey[0].toInt())
        assertEquals(3, session.profiles.getValue("one").swapKey[0].toInt())
        assertEquals("one", session.assignments["org.example.app"])
    }
    private class MemorySettings : SettingsStore {
        var value: String? = null
        var failWrite = false
        var beforeRead: (suspend () -> Unit)? = null
        var afterCommit: (suspend () -> Unit)? = null
        override suspend fun read(): String? {
            beforeRead?.invoke()
            return value
        }
        override suspend fun write(value: String) {
            if (failWrite) error("simulated write failure")
            this.value = value
            afterCommit?.invoke()
        }
    }
    private class MemorySecrets : SecretStore {
        val values = mutableMapOf<String, SecretKeys>()
        var afterPut: (suspend () -> Unit)? = null
        override suspend fun put(ref: String, keys: SecretKeys) {
            values[ref] = keys
            afterPut?.invoke()
        }
        override suspend fun get(ref: String): SecretKeys = values[ref] ?: throw SecretUnavailable()
        override suspend fun delete(ref: String) { values.remove(ref) }
    }
    private val keys = SecretKeys(ByteArray(128) { it.toByte() }, ByteArray(8) { it.toByte() })

    @Test fun versionTwoMigrationPreservesScopeDnsAndSecretReference() = runBlocking {
        val settings = MemorySettings()
        val repository = SettingsRepository(settings, MemorySecrets()) { false }
        val profile = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        val raw = ByteArrayOutputStream()
        DataOutputStream(raw).use { out ->
            out.writeInt(2); out.writeInt(1)
            out.writeUTF(profile.id); out.writeUTF(profile.name); out.writeUTF(profile.address)
            out.writeInt(profile.firstPort); out.writeInt(profile.lastPort); out.writeUTF(profile.secretRef)
            out.writeBoolean(true); out.writeUTF(profile.id)
            out.writeInt(1); out.writeUTF("org.example.app"); out.writeUTF(profile.id)
            out.writeBoolean(true); out.writeUTF(profile.id)
        }
        settings.value = Base64.getEncoder().encodeToString(raw.toByteArray())
        val restored = repository.load()
        assertEquals(4, restored.schemaVersion)
        assertEquals(CaptureMode.ASSIGNED_APPS, restored.captureMode)
        assertEquals(profile.secretRef, restored.profiles.single().secretRef)
        assertEquals(profile.id, restored.dnsProfileId)
        assertEquals(profile.id, restored.assignments["org.example.app"])
        assertEquals(restored, SettingsCodec.decode(SettingsCodec.encode(restored)))
    }

    @Test fun domainOnlyProfilePersistsAndCannotBeDeleted() = runBlocking {
        val settings = MemorySettings()
        val repository = SettingsRepository(settings, MemorySecrets()) { false }
        val profile = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        val rule = repository.saveDomainRule(null, profile.id, "*.BÜCHER.Example.").domainRules.single()
        assertEquals("*.xn--bcher-kva.example", rule.pattern)
        assertEquals(profile.id, repository.load().dnsProfileId)
        assertThrows(IllegalArgumentException::class.java) { runBlocking { repository.deleteProfile(profile.id) } }
        assertEquals(rule, SettingsCodec.decode(settings.value).domainRules.single())
        assertEquals(CaptureMode.ASSIGNED_APPS, repository.load().captureMode)
        assertEquals(1, repository.snapshot(emptySet(), true).domainRules.size)
    }

    @Test fun versionThreeMigrationKeepsPublicCaptureAndIpv4Rule() = runBlocking {
        val store = MemorySettings(); val secrets = MemorySecrets()
        val repository = SettingsRepository(store, secrets) { false }
        val profile = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        val id = java.util.UUID.randomUUID().toString()
        val raw = ByteArrayOutputStream()
        DataOutputStream(raw).use { out ->
            out.writeInt(3); out.writeInt(1)
            out.writeUTF(profile.id); out.writeUTF(profile.name); out.writeUTF(profile.address)
            out.writeInt(profile.firstPort); out.writeInt(profile.lastPort); out.writeUTF(profile.secretRef)
            out.writeBoolean(true); out.writeUTF(profile.id)
            out.writeInt(0)
            out.writeBoolean(true); out.writeUTF(profile.id)
            out.writeUTF(CaptureMode.PUBLIC_IPV4_RULES.name)
            out.writeInt(1); out.writeUTF(id); out.writeUTF(profile.id); out.writeUTF("8.8.9.0/24")
        }
        store.value = Base64.getEncoder().encodeToString(raw.toByteArray())
        val migrated = repository.load()
        assertEquals(4, migrated.schemaVersion)
        assertEquals(CaptureMode.PUBLIC_IPV4_RULES, migrated.captureMode)
        assertEquals(profile.secretRef, migrated.profiles.single().secretRef)
        assertEquals(id, migrated.ipv4Rules.single().id)
        assertEquals(profile.id, migrated.dnsProfileId)
        assertTrue(migrated.domainRules.isEmpty())
    }

    @Test fun ipOnlyProfileRulesPersistAndCannotBeDeleted() = runBlocking {
        val settings = MemorySettings()
        val repository = SettingsRepository(settings, MemorySecrets()) { false }
        val first = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        val second = repository.saveProfile(null, "Two", "9.9.9.9", "2000", "2000", keys).profiles.last()
        val rule = repository.saveIpv4Rule(null, second.id, "8.8.9.5/23").ipv4Rules.single()
        assertEquals("8.8.8.0/23", rule.expression)
        assertEquals(rule, repository.load().ipv4Rules.single())
        assertEquals(first.secretRef, repository.load().profiles.first().secretRef)
        assertEquals(second.secretRef, repository.load().profiles.last().secretRef)
        assertThrows(IllegalArgumentException::class.java) { runBlocking { repository.deleteProfile(second.id) } }
        assertThrows(SettingsCorrupt::class.java) {
            runBlocking { repository.saveIpv4Rule(null, first.id, "8.8.9.255") }
        }
        assertEquals(second.id, repository.selectDnsProfile(second.id).dnsProfileId)
        repository.assignPackage("org.example.app", first.id)
        assertEquals(setOf(first.id), repository.snapshot(setOf("org.example.app"), false).profiles.keys)
        val publicSnapshot = repository.snapshot(setOf("org.example.app"), true)
        assertEquals(CaptureMode.PUBLIC_IPV4_RULES, publicSnapshot.captureMode)
        assertEquals(rule.id, publicSnapshot.ipv4Rules.single().id)
        repository.assignPackage("org.example.app", null)
        assertEquals(setOf(second.id), repository.snapshot(emptySet(), true).profiles.keys)
        repository.deleteIpv4Rule(rule.id)
        assertEquals(first.id, repository.deleteProfile(second.id).activeProfileId)
    }

    @Test fun saveLoadEditSelectAndDeleteKeepIds() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val first = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1001", keys).profiles.single()
        val second = repository.saveProfile(null, "Two", "1.1.1.1", "2000", "2001", keys).profiles.last()
        assertEquals(first.id, repository.load().activeProfileId)
        assertEquals(first.id, repository.saveProfile(first.id, "Renamed", "8.8.4.4", "1000", "1002", null).profiles.first().id)
        assertEquals(second.id, repository.selectProfile(second.id).activeProfileId)
        assertEquals(first.id, repository.deleteProfile(second.id).activeProfileId)
        assertEquals("Renamed", repository.load().profiles.single().name)
        assertEquals(1, secrets.values.size)
        assertFalse(settings.value!!.contains("Renamed")) // document is encoded, and never contains keys
        assertFalse(settings.value!!.contains(Base64.getEncoder().encodeToString(keys.xor)))
    }

    @Test fun renameKeepsEndpointAndSecretWithoutSshSettings() = runBlocking {
        val secrets = MemorySecrets()
        val repository = SettingsRepository(MemorySettings(), secrets) { false }
        val original = repository.saveProfile(null, "One", "8.8.8.8", "2000", "2001", keys).profiles.single()
        val renamed = repository.renameProfile(original.id, "New name", "008.008.008.008").profiles.single()
        assertEquals(original.copy(name = "New name"), renamed)
        assertEquals(setOf(original.secretRef), secrets.values.keys)
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { repository.renameProfile(original.id, "Wrong address", "8.8.4.4") }
        }
        assertEquals(renamed, repository.load().profiles.single())
    }

    @Test fun writeFailureRollsBackNewSecretAndOldConfiguration() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val old = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys)
        val before = settings.value
        settings.failWrite = true
        assertThrows(IllegalStateException::class.java) {
            runBlocking { repository.saveProfile(old.profiles.single().id, "Changed", "8.8.4.4", "1000", "1000", keys) }
        }
        assertEquals(before, settings.value)
        assertTrue(old.profiles.single().secretRef in secrets.values)
        assertTrue(secrets.values.keys.containsAll(repository.load().profiles.map { it.secretRef }))
    }

    @Test fun damagedAndFutureSchemaAreNotOverwritten() = runBlocking {
        val settings = MemorySettings()
        val repository = SettingsRepository(settings, MemorySecrets()) { false }
        settings.value = "!not base64!"
        assertThrows(SettingsCorrupt::class.java) { runBlocking { repository.load() } }
        assertEquals("!not base64!", settings.value)
        settings.value = Base64.getEncoder().encodeToString(byteArrayOf(0, 0, 0, 2))
        assertThrows(SettingsCorrupt::class.java) { runBlocking { repository.load() } }
        assertNotNull(settings.value)
    }

    @Test fun keysAndSelectionMustBeValid() = runBlocking {
        assertThrows(IllegalArgumentException::class.java) { SessionValidator.keyBase64("not*base64", 128) }
        assertThrows(IllegalArgumentException::class.java) { SessionValidator.keyBase64(Base64.getEncoder().encodeToString(ByteArray(127)), 128) }
        assertThrows(IllegalArgumentException::class.java) { SessionValidator.keyBase64(Base64.getEncoder().encodeToString(ByteArray(7)), 8) }
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val saved = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys)
        assertThrows(IllegalArgumentException::class.java) { runBlocking { repository.snapshot(setOf("org.example.app"), false) } }
        repository.togglePackage("org.example.app")
        assertThrows(IllegalArgumentException::class.java) { runBlocking { repository.snapshot(emptySet(), false) } }
        val snapshot = repository.snapshot(setOf("org.example.app"), false)
        assertEquals("8.8.8.8", snapshot.serverAddress)
        assertEquals(setOf("org.example.app"), snapshot.packages)
        assertArrayEquals(keys.xor, snapshot.xorKey)
        secrets.values.clear() // Testable boundary: lost key, not an Android Keystore test.
        assertThrows(SecretUnavailable::class.java) { runBlocking { repository.snapshot(setOf("org.example.app"), false) } }
        assertEquals(saved.profiles.single().id, repository.load().activeProfileId)
    }

    @Test fun activeSessionBlocksAllMutations() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        var active = false
        val repository = SettingsRepository(settings, secrets) { active }
        val profile = repository.saveProfile(null, "One", "8.8.8.8", "1000", "1000", keys).profiles.single()
        active = true
        assertThrows(IllegalStateException::class.java) { runBlocking { repository.saveProfile(profile.id, "Edit", "8.8.8.8", "1000", "1000", null) } }
        assertThrows(IllegalStateException::class.java) { runBlocking { repository.deleteProfile(profile.id) } }
        assertThrows(IllegalStateException::class.java) { runBlocking { repository.selectProfile(profile.id) } }
        assertThrows(IllegalStateException::class.java) { runBlocking { repository.togglePackage("org.example.app") } }
        Unit
    }

    @Test fun cancellationBeforeWriteLeavesOldStateAndNoNewKey() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val reading = CompletableDeferred<Unit>()
        val continueRead = CompletableDeferred<Unit>()
        settings.beforeRead = { reading.complete(Unit); continueRead.await() }
        val operation = async { repository.saveProfile(null, "New", "8.8.8.8", "1000", "1000", keys) }
        withTimeout(3000) { reading.await() }
        operation.cancel()
        continueRead.complete(Unit)
        operation.join()
        assertTrue(operation.isCancelled)
        assertNull(settings.value)
        assertTrue(secrets.values.isEmpty())
    }

    @Test fun cancellationAfterCommitKeepsReferencedNewKey() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val committed = CompletableDeferred<Unit>()
        val acknowledge = CompletableDeferred<Unit>()
        settings.afterCommit = { committed.complete(Unit); acknowledge.await() }
        val operation = async { repository.saveProfile(null, "New", "8.8.8.8", "1000", "1000", keys) }
        withTimeout(3000) { committed.await() }
        operation.cancel()
        acknowledge.complete(Unit)
        operation.join()
        assertTrue(operation.isCancelled)
        val saved = repository.load()
        assertEquals(1, saved.profiles.size)
        assertTrue(saved.profiles.single().secretRef in secrets.values)
    }

    @Test fun cancellationDuringReplacementPreservesCommittedKey() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val previous = repository.saveProfile(null, "Old", "8.8.8.8", "1000", "1000", keys).profiles.single()
        val putDone = CompletableDeferred<Unit>()
        val continuePut = CompletableDeferred<Unit>()
        secrets.afterPut = { putDone.complete(Unit); continuePut.await() }
        val operation = async { repository.saveProfile(previous.id, "New", "8.8.4.4", "1000", "1000", keys) }
        withTimeout(3000) { putDone.await() }
        assertEquals(previous.secretRef, SettingsCodec.decode(settings.value).profiles.single().secretRef)
        assertTrue(previous.secretRef in secrets.values)
        operation.cancel()
        continuePut.complete(Unit)
        operation.join()
        val current = repository.load().profiles.single()
        assertEquals(previous.id, current.id)
        assertTrue(current.secretRef in secrets.values)
    }

    @Test fun cancellationDuringDeleteCannotLeaveReferencedKeyDeleted() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val profile = repository.saveProfile(null, "Old", "8.8.8.8", "1000", "1000", keys).profiles.single()
        val committed = CompletableDeferred<Unit>()
        val acknowledge = CompletableDeferred<Unit>()
        settings.afterCommit = { committed.complete(Unit); acknowledge.await() }
        val operation = async { repository.deleteProfile(profile.id) }
        withTimeout(3000) { committed.await() }
        operation.cancel()
        acknowledge.complete(Unit)
        operation.join()
        assertTrue(repository.load().profiles.isEmpty())
        assertTrue(repository.load().profiles.all { it.secretRef in secrets.values })
    }

    @Test fun failedDeleteWriteRetainsReferencedKey() = runBlocking {
        val settings = MemorySettings()
        val secrets = MemorySecrets()
        val repository = SettingsRepository(settings, secrets) { false }
        val profile = repository.saveProfile(null, "Old", "8.8.8.8", "1000", "1000", keys).profiles.single()
        settings.failWrite = true
        assertThrows(IllegalStateException::class.java) { runBlocking { repository.deleteProfile(profile.id) } }
        assertEquals(profile.id, repository.load().profiles.single().id)
        assertTrue(profile.secretRef in secrets.values)
    }

    @Test fun blockingSecretWorkRunsOnDispatcherThread() = runBlocking {
        val caller = Thread.currentThread()
        val seen = mutableListOf<Thread>()
        val blocking = object : BlockingSecretStore {
            override fun put(ref: String, keys: SecretKeys) { seen.add(Thread.currentThread()) }
            override fun get(ref: String): SecretKeys { seen.add(Thread.currentThread()); return keys }
            override fun delete(ref: String) { seen.add(Thread.currentThread()) }
        }
        Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { dispatcher ->
            val store = DispatchingSecretStore(blocking, dispatcher)
            store.put("ref", keys)
            store.get("ref")
            store.delete("ref")
        }
        assertEquals(3, seen.size)
        assertTrue(seen.all { it != caller })
        assertEquals(1, seen.toSet().size)
    }
}
