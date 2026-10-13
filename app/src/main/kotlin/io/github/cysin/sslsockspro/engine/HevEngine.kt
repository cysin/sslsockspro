package io.github.cysin.sslsockspro.engine

class HevEngine {
    external fun TProxyStartService(configuration: String, descriptor: Int): Boolean
    external fun TProxyStopService(): Boolean
    external fun TProxyIsRunning(): Boolean
    external fun TProxyGetStats(): LongArray
    companion object { init { System.loadLibrary("hev-socks5-tunnel") } }
}
