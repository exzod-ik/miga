package org.miga.android

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.Base64
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class SettingsMigrationTest {
    private val first = "11111111-1111-4111-8111-111111111111"
    private val second = "22222222-2222-4222-8222-222222222222"
    private val firstSecret = "33333333-3333-4333-8333-333333333333"
    private val secondSecret = "44444444-4444-4444-8444-444444444444"
    private val ipRule = "55555555-5555-4555-8555-555555555555"
    private val domainRule = "66666666-6666-4666-8666-666666666666"

    private fun document(version: Int, duplicateProfile: Boolean = false, missingRuleProfile: Boolean = false): String {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeInt(version)
            out.writeInt(2)
            listOf(Triple(first, "First", firstSecret), Triple(if (duplicateProfile) first else second, "Second", secondSecret))
                .forEachIndexed { index, (id, name, secret) ->
                    out.writeUTF(id)
                    out.writeUTF(name)
                    out.writeUTF(if (index == 0) "8.8.8.8" else "1.1.1.1")
                    out.writeInt(2000)
                    out.writeInt(3000)
                    out.writeUTF(secret)
                }
            out.writeBoolean(true)
            out.writeUTF(first)
            out.writeInt(2)
            out.writeUTF("org.example.one")
            if (version != 1) out.writeUTF(first)
            out.writeUTF("org.example.two")
            if (version != 1) out.writeUTF(second)
            if (version >= 2) {
                out.writeBoolean(true)
                out.writeUTF(second)
            }
            if (version >= 3) {
                out.writeUTF("PUBLIC_IPV4_RULES")
                out.writeInt(1)
                out.writeUTF(ipRule)
                out.writeUTF(if (missingRuleProfile) firstSecret else second)
                out.writeUTF("9.9.9.0/24")
            }
            if (version >= 4) {
                out.writeInt(1)
                out.writeUTF(domainRule)
                out.writeUTF(first)
                out.writeUTF("*.example.org")
            }
        }
        return Base64.getEncoder().encodeToString(bytes.toByteArray())
    }

    private class Store(var value: String?) : SettingsStore {
        var writes = 0
        var failBefore = false
        var failAfter = false
        override suspend fun read() = value
        override suspend fun write(value: String) {
            if (failBefore) error("write failed")
            this.value = value
            writes++
            if (failAfter) error("acknowledgement failed")
        }
    }

    private class Secrets : SecretStore {
        val values = mutableMapOf<String, InvitationSecret>()
        val reads = mutableListOf<String>()
        val deleted = mutableListOf<String>()
        override suspend fun get(ref: String): InvitationSecret {
            reads.add(ref)
            return values[ref] ?: throw SecretUnavailable()
        }
        override suspend fun put(ref: String, keys: InvitationSecret) { values[ref] = keys }
        override suspend fun delete(ref: String) { deleted.add(ref); values.remove(ref) }
    }

    @Test fun allLegacySchemasPreserveRulesAndRequireInvitationsWithoutReadingKeys() = runBlocking<Unit> {
        for (version in 1..4) {
            val store = Store(document(version))
            val secrets = Secrets()
            val repository = SettingsRepository(store, secrets) { false }
            val saved = repository.load()
            assertEquals(6, saved.schemaVersion)
            assertEquals(listOf(first, second), saved.profiles.map { it.id })
            assertEquals(listOf("First", "Second"), saved.profiles.map { it.name })
            assertEquals(first, saved.activeProfileId)
            assertEquals(mapOf("org.example.one" to first, "org.example.two" to if (version == 1) first else second), saved.assignments)
            assertEquals(if (version >= 3) listOf(SavedIpv4Rule(ipRule, second, "9.9.9.0/24")) else emptyList<SavedIpv4Rule>(), saved.ipv4Rules)
            assertEquals(if (version >= 4) listOf(SavedDomainRule(domainRule, first, "*.example.org")) else emptyList<SavedDomainRule>(), saved.domainRules)
            assertTrue(saved.profiles.all { it.requiresInvitation })
            assertEquals(saved, SettingsCodec.decode(store.value))
            assertEquals(saved, repository.load())
            assertEquals(1, store.writes)
            assertTrue(secrets.reads.isEmpty())
            assertTrue(secrets.values.isEmpty())
            assertTrue(secrets.deleted.isEmpty())
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking { repository.snapshot(saved.selectedPackages, true) }
            }
            assertTrue(secrets.reads.isEmpty())
        }
    }

    @Test fun schemaFiveKeepsWorkingInvitationReferences() = runBlocking<Unit> {
        val store = Store(document(5))
        val secrets = Secrets()
        secrets.values[firstSecret] = InvitationSecret(testInvitation("8.8.8.8", 2000, 3000))
        secrets.values[secondSecret] = InvitationSecret(testInvitation("1.1.1.1", 2000, 3000))
        val repository = SettingsRepository(store, secrets) { false }
        val saved = repository.load()
        assertTrue(saved.profiles.none { it.requiresInvitation })
        assertEquals(listOf(firstSecret, secondSecret), saved.profiles.map { it.secretRef })
        assertEquals(setOf(first, second), repository.snapshot(saved.selectedPackages, true).profiles.keys)
        assertTrue(secrets.deleted.isEmpty())
    }

    @Test fun replacementCanChangeAddressWithoutLosingRulesAndOtherProfilesStayBlocked() = runBlocking<Unit> {
        val store = Store(document(4))
        val secrets = Secrets()
        val repository = SettingsRepository(store, secrets) { false }
        val before = repository.load()
        val updated = repository.saveProfile(first, "Renamed", "8.8.4.4", "10000", "15000",
            InvitationSecret(testInvitation("8.8.4.4", 10000, 15000)))
        assertEquals(before.assignments, updated.assignments)
        assertEquals(before.ipv4Rules, updated.ipv4Rules)
        assertEquals(before.domainRules, updated.domainRules)
        assertFalse(updated.profiles.first().requiresInvitation)
        assertTrue(updated.profiles.last().requiresInvitation)
        assertNotEquals(firstSecret, updated.profiles.first().secretRef)
        assertEquals(listOf(firstSecret), secrets.deleted)
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { repository.snapshot(updated.selectedPackages, true) }
        }
        assertTrue(secrets.reads.isEmpty())
        repository.saveProfile(second, "Second", "1.1.1.1", "10000", "15000",
            InvitationSecret(testInvitation("1.1.1.1", 10000, 15000)))
        assertEquals("8.8.4.4", repository.snapshot(updated.selectedPackages, true).profiles.getValue(first).serverAddress)
        assertTrue(repository.load().profiles.none { it.requiresInvitation })
    }

    @Test fun renamingAndEditingRulesDoNotUnlockMigratedProfile() = runBlocking<Unit> {
        val repository = SettingsRepository(Store(document(4)), Secrets()) { false }
        repository.renameProfile(first, "Renamed", "8.8.8.8")
        repository.saveDomainRule(domainRule, first, "*.new.example.org")
        repository.saveProfile(first, "Still pending", "8.8.8.8", "2000", "3000", null)
        assertTrue(repository.load().profiles.all { it.requiresInvitation })
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { repository.snapshot(setOf("org.example.one", "org.example.two"), true) }
        }
    }

    @Test fun malformedLegacySettingsAreNeverOverwritten() = runBlocking<Unit> {
        val valid = Base64.getDecoder().decode(document(4))
        val invalid = listOf("!not base64!", document(7), document(4, duplicateProfile = true),
            document(4, missingRuleProfile = true),
            Base64.getEncoder().encodeToString(valid.copyOf(valid.size - 1)),
            Base64.getEncoder().encodeToString(valid + byteArrayOf(0)))
        for (raw in invalid) {
            val store = Store(raw)
            assertThrows(SettingsCorrupt::class.java) {
                runBlocking { SettingsRepository(store, Secrets()) { false }.load() }
            }
            assertEquals(raw, store.value)
            assertEquals(0, store.writes)
        }
    }

    @Test fun migrationWriteFailurePreservesSourceAndCanBeRetried() = runBlocking<Unit> {
        val source = document(4)
        val store = Store(source).also { it.failBefore = true }
        val repository = SettingsRepository(store, Secrets()) { false }
        assertThrows(IllegalStateException::class.java) { runBlocking { repository.load() } }
        assertEquals(source, store.value)
        store.failBefore = false
        assertTrue(repository.load().profiles.all { it.requiresInvitation })
        assertEquals(1, store.writes)
    }

    @Test fun failedMigrationAcknowledgementDoesNotRepeatCommittedMigration() = runBlocking<Unit> {
        val store = Store(document(4)).also { it.failAfter = true }
        val repository = SettingsRepository(store, Secrets()) { false }
        assertThrows(IllegalStateException::class.java) { runBlocking { repository.load() } }
        store.failAfter = false
        assertTrue(repository.load().profiles.all { it.requiresInvitation })
        assertEquals(1, store.writes)
    }

    @Test fun failedInvitationWriteLeavesMigratedRulesAndOldSecretUntouched() = runBlocking<Unit> {
        val store = Store(document(4))
        val secrets = Secrets()
        val repository = SettingsRepository(store, secrets) { false }
        val before = repository.load()
        store.failBefore = true
        assertThrows(IllegalStateException::class.java) {
            runBlocking { repository.saveProfile(first, "First", "8.8.4.4", "10000", "15000",
                InvitationSecret(testInvitation("8.8.4.4", 10000, 15000))) }
        }
        assertEquals(before, repository.load())
        assertTrue(secrets.deleted.isEmpty())
    }

    @Test fun migrationDoesNotWriteWhileSessionIsActive() = runBlocking<Unit> {
        val source = document(4)
        val store = Store(source)
        assertThrows(IllegalStateException::class.java) {
            runBlocking { SettingsRepository(store, Secrets()) { true }.load() }
        }
        assertEquals(source, store.value)
    }

    @Test fun emptyInstallDoesNotWriteOrRequireInvitation() = runBlocking<Unit> {
        val store = Store(null)
        assertEquals(SavedSettings(), SettingsRepository(store, Secrets()) { false }.load())
        assertEquals(0, store.writes)
    }

    @Test fun unusedPendingProfileDoesNotBlockReadyRoutes() = runBlocking<Unit> {
        val repository = SettingsRepository(Store(document(4)), Secrets()) { false }
        repository.load()
        repository.saveProfile(first, "First", "8.8.8.8", "10000", "15000",
            InvitationSecret(testInvitation("8.8.8.8", 10000, 15000)))
        repository.assignPackage("org.example.two", null)
        repository.deleteIpv4Rule(ipRule)
        val session = repository.snapshot(setOf("org.example.one"), true)
        assertEquals(setOf(first), session.profiles.keys)
        assertEquals(listOf(domainRule), session.domainRules.map { it.id })
        assertTrue(repository.load().profiles.last().requiresInvitation)
    }

    @Test fun invalidInvitationCannotUnlockMigratedProfile() = runBlocking<Unit> {
        val store = Store(document(4))
        val secrets = Secrets()
        val repository = SettingsRepository(store, secrets) { false }
        val before = repository.load()
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { repository.saveProfile(first, "First", "8.8.8.8", "10000", "15000",
                InvitationSecret(testInvitation("1.1.1.1", 10000, 15000))) }
        }
        assertEquals(before, repository.load())
        assertTrue(secrets.values.isEmpty())
        assertTrue(secrets.deleted.isEmpty())
    }
}
