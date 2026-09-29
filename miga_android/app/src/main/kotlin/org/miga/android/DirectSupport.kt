package org.miga.android

import android.content.Context
import android.os.Build
import java.io.File
import java.util.zip.ZipFile

/** A source-built native library must be packaged for the running ABI. */
object DirectSupport {
    fun available(context: Context): Boolean {
        val library = "libhev-socks5-tunnel.so"
        if (File(context.applicationInfo.nativeLibraryDir, library).isFile) return true
        // Modern Android can load uncompressed .so files directly from the APK.
        val packages = listOfNotNull(context.applicationInfo.sourceDir) +
            context.applicationInfo.splitSourceDirs.orEmpty()
        return packages.any { path ->
            runCatching {
                ZipFile(path).use { archive ->
                    Build.SUPPORTED_ABIS.any { abi -> archive.getEntry("lib/$abi/$library") != null }
                }
            }.getOrDefault(false)
        }
    }
}
