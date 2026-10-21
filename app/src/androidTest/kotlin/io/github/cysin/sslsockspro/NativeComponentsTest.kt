package io.github.cysin.sslsockspro

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.cysin.sslsockspro.engine.HevEngine
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class NativeComponentsTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun version(binary: String, argument: String): String {
        val executable = File(context.applicationInfo.nativeLibraryDir, binary)
        assertTrue("Native executable was not extracted", executable.canExecute())
        val child = ProcessBuilder(executable.absolutePath, argument).redirectErrorStream(true).start()
        try {
            val output = child.inputStream.bufferedReader().readText()
            assertTrue("Native executable did not finish", child.waitFor(10, TimeUnit.SECONDS))
            assertEquals(output, 0, child.exitValue())
            return output
        } finally { if (child.isAlive) child.destroyForcibly() }
    }

    @Test fun packagedStunnelRunsOnAndroid16() {
        val output = version("libstunnel_exec.so", "-version")
        assertTrue(output, output.contains("5.82"))
        assertTrue(output, output.contains("4.0.3"))
    }

    @Test fun packagedOpenVpnRunsOnAndroid16() {
        val output = version("libopenvpn_exec.so", "--version")
        assertTrue(output, output.contains("2.7.8"))
        assertTrue(output, output.contains("4.0.3"))
    }

    @Test fun packetEngineJniLoadsAndReportsIdle() {
        assertFalse(HevEngine().TProxyIsRunning())
    }

    /** Engines holding keys are not dumpable: even this app's other
     * processes cannot read their memory or environment. */
    @Test fun nativeEnginesAreNotDumpable() {
        val executable = File(context.applicationInfo.nativeLibraryDir, "libopenvpn_exec.so")
        // Process.pid() needs API 37: the shell prints its PID, then becomes
        // the engine, which waits for its configuration on stdin.
        val child = ProcessBuilder("/system/bin/sh", "-c", "echo \$\$; exec \"\$0\" --config /dev/stdin", executable.absolutePath).start()
        try {
            val pid = child.inputStream.bufferedReader().readLine()!!.trim().toInt()
            Thread.sleep(300)
            assertTrue("The engine must still be running", child.isAlive)
            assertThrows(java.io.IOException::class.java) { File("/proc/$pid/environ").readBytes() }
        } finally { child.destroyForcibly(); child.waitFor(5, TimeUnit.SECONDS) }
    }
}
