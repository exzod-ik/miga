package org.miga.android

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import hev.htproxy.TProxyService

/** Confirms that Android can load the packaged library and register its JNI methods. */
class NativeLoadInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        super.onStart()
        val result = Bundle()
        try {
            TProxyService.TProxyIsRunning()
            result.putString("nativeLoad", "ok")
            finish(Activity.RESULT_OK, result)
        } catch (failure: Throwable) {
            result.putString("nativeLoad", failure.javaClass.simpleName)
            finish(Activity.RESULT_CANCELED, result)
        }
    }
}
