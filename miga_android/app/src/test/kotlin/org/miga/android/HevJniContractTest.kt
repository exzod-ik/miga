package org.miga.android

import java.lang.reflect.Method
import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HevJniContractTest {
    @Test fun pinnedHev2171NativeMethodsMatchWithoutLoadingTheLibrary() {
        // src/hev-jni.c at 9a06bc6e7989da54e3d32ff701ef7a7ce4995d3a.
        val clazz = Class.forName("hev.htproxy.TProxyService", false, javaClass.classLoader)
        assertEquals("hev/htproxy/TProxyService", clazz.name.replace('.', '/'))
        val nativeMethods = clazz.declaredMethods.filter { Modifier.isNative(it.modifiers) }
        assertEquals(4, nativeMethods.size)
        val actual = nativeMethods.associate { it.name to it.descriptor() }
        assertEquals(mapOf(
            "TProxyStartService" to "(Ljava/lang/String;I)Z",
            "TProxyStopService" to "()Z",
            "TProxyIsRunning" to "()Z",
            "TProxyGetStats" to "()[J",
        ), actual)
        assertTrue(clazz.declaredMethods.filter { it.name in actual.keys }
            .all { Modifier.isNative(it.modifiers) })
    }

    private fun Method.descriptor(): String =
        parameterTypes.joinToString("", "(", ")") { it.descriptor() } + returnType.descriptor()

    private fun Class<*>.descriptor(): String = when {
        isArray -> name.replace('.', '/')
        isPrimitive -> when (name) {
            "void" -> "V"
            "boolean" -> "Z"
            "byte" -> "B"
            "char" -> "C"
            "short" -> "S"
            "int" -> "I"
            "long" -> "J"
            "float" -> "F"
            "double" -> "D"
            else -> error("Unknown primitive $name")
        }
        else -> "L${name.replace('.', '/')};"
    }
}
