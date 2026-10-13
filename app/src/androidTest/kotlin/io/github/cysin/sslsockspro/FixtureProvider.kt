package io.github.cysin.sslsockspro

import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import io.github.cysin.sslsockspro.data.PackageImporter

fun readTestFixture(name: String): ByteArray {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    return context.contentResolver.openInputStream(Uri.parse("content://io.github.cysin.sslsockspro.test.fixtures/$name"))!!.use {
        PackageImporter.boundedRead(it, PackageImporter.MAX_TOTAL)
    }
}
