package org.miga.android

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import android.content.Intent
import hev.htproxy.TProxyService
import org.junit.runner.JUnitCore
import org.junit.runner.Description
import org.junit.runner.Request
import org.junit.runner.notification.RunListener
import org.miga.core.LocalDirectSocksTest
import org.miga.core.LocalDirectSocksIdleTest
import org.miga.core.LocalDirectSocksStallTest

/** Confirms that Android can load the packaged library and register its JNI methods. */
class NativeLoadInstrumentation : Instrumentation() {
    private var suite = "native"
    private var selectedTest: String? = null

    override fun onCreate(arguments: Bundle?) {
        suite = arguments?.getString("suite") ?: "native"
        selectedTest = arguments?.getString("test")
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        super.onStart()
        val result = Bundle()
        try {
            if (targetContext.packageName == "org.miga.android.devicechecks") {
                startActivitySync(Intent().setClassName(targetContext.packageName,
                    "org.miga.android.devicechecks.CheckActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
            require(suite == "native" || suite == "direct") { "Unknown test suite" }
            if (suite == "direct") {
                val runnerThread = Thread.currentThread()
                val watchdog = Thread({
                    try {
                        Thread.sleep(90_000)
                        val timeout = Bundle()
                        timeout.putString("timeout", "DIRECT suite exceeded 90 seconds")
                        sendStatus(-1, timeout)
                        timeout.putString("runnerStack", runnerThread.stackTrace.joinToString("\n"))
                        finish(Activity.RESULT_CANCELED, timeout)
                    } catch (_: InterruptedException) { }
                }, "device-check-watchdog").apply { isDaemon = true; start() }
                val runner = JUnitCore()
                runner.addListener(object : RunListener() {
                    override fun testStarted(description: Description) {
                        sendStatus(1, Bundle().apply { putString("test", description.displayName) })
                    }
                    override fun testFinished(description: Description) {
                        sendStatus(0, Bundle().apply { putString("finished", description.displayName) })
                    }
                })
                val tests = try {
                    val classes = listOf(LocalDirectSocksTest::class.java,
                        LocalDirectSocksIdleTest::class.java, LocalDirectSocksStallTest::class.java)
                    val requested = selectedTest
                    if (requested == null) runner.run(*classes.toTypedArray()) else {
                        val parts = requested.split("#", limit = 2)
                        require(parts.size == 2) { "Expected Class#method" }
                        val type = classes.single { it.simpleName == parts[0] }
                        runner.run(Request.method(type, parts[1]))
                    }
                } finally { watchdog.interrupt() }
                result.putInt("tests", tests.runCount)
                result.putInt("failures", tests.failureCount)
                result.putInt("ignored", tests.ignoreCount)
                result.putLong("elapsedMillis", tests.runTime)
                result.putString("details", tests.failures.joinToString("\n") { "${it.testHeader}: ${it.trace}" })
                finish(if (tests.wasSuccessful()) Activity.RESULT_OK else Activity.RESULT_CANCELED, result)
                return
            }
            TProxyService.TProxyIsRunning()
            check(ProtocolV2Native.port(0L) == 0)
            result.putString("nativeLoad", "ok")
            finish(Activity.RESULT_OK, result)
        } catch (failure: Throwable) {
            result.putString("nativeLoad", failure.javaClass.simpleName)
            finish(Activity.RESULT_CANCELED, result)
        }
    }
}
