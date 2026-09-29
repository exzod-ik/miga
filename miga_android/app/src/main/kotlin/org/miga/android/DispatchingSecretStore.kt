package org.miga.android

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Blocking implementations stay behind this boundary, including future callers from the UI. */
interface BlockingSecretStore {
    fun put(ref: String, keys: SecretKeys)
    fun get(ref: String): SecretKeys
    fun delete(ref: String)
}

class DispatchingSecretStore(
    private val blocking: BlockingSecretStore,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : SecretStore {
    override suspend fun put(ref: String, keys: SecretKeys) = withContext(dispatcher) { blocking.put(ref, keys) }
    override suspend fun get(ref: String): SecretKeys = withContext(dispatcher) { blocking.get(ref) }
    override suspend fun delete(ref: String) = withContext(dispatcher) { blocking.delete(ref) }
}
