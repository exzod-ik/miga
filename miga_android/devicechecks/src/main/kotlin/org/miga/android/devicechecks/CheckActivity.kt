package org.miga.android.devicechecks

import android.app.Activity
import android.os.Bundle
import android.view.WindowManager
import android.widget.TextView

class CheckActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        setContentView(TextView(this).apply {
            text = "MIGA device checks are running.\nKeep this window visible until it closes."
            textSize = 20f
            setPadding(40, 80, 40, 40)
        })
    }
}
