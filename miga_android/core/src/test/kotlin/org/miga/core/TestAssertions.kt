package org.miga.core

import org.junit.Assert

fun assertContentEquals(expected: ByteArray, actual: ByteArray?, message: String = "") =
    Assert.assertArrayEquals(message, expected, actual)

fun assertEquals(expected: Any?, actual: Any?) = Assert.assertEquals(expected, actual)
fun assertNotEquals(expected: Any?, actual: Any?) = Assert.assertNotEquals(expected, actual)
fun assertNull(actual: Any?) = Assert.assertNull(actual)
fun <T : Any> assertNotNull(actual: T?): T { Assert.assertNotNull(actual); return actual!! }
inline fun <reified T : Throwable> assertFailsWith(block: () -> Unit) {
    try { block() } catch (exception: Throwable) {
        if (exception is T) return
        throw AssertionError("Expected ${T::class.java.name}, got ${exception.javaClass.name}", exception)
    }
    throw AssertionError("Expected ${T::class.java.name}")
}
