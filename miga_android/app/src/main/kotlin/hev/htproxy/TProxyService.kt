package hev.htproxy

/** JNI contract from hev-socks5-tunnel 2.17.1. Loaded only for DIRECT sessions. */
object TProxyService {
    init { System.loadLibrary("hev-socks5-tunnel") }

    external fun TProxyStartService(configPath: String, fd: Int): Boolean
    external fun TProxyStopService(): Boolean
    external fun TProxyIsRunning(): Boolean
    external fun TProxyGetStats(): LongArray
}
