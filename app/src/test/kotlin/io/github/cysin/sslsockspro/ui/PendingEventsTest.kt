package io.github.cysin.sslsockspro.ui

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PendingEventsTest {
    @Test fun sharedFileStaysPendingUntilItsSuspendedReadCompletes() = runTest {
        val pending = MutableStateFlow<String?>("shared package")
        val read = CompletableDeferred<Unit>()
        val imported = mutableListOf<String>()
        backgroundScope.launch { pending.consumePending { read.await(); imported += it } }
        runCurrent()
        assertEquals("shared package", pending.value)
        assertTrue(imported.isEmpty())
        read.complete(Unit)
        runCurrent()
        assertEquals(listOf("shared package"), imported)
        assertNull(pending.value)
    }

    @Test fun anotherShareDuringTheFirstReadIsNotDiscarded() = runTest {
        val pending = MutableStateFlow<String?>("first")
        val firstRead = CompletableDeferred<Unit>()
        val imported = mutableListOf<String>()
        backgroundScope.launch { pending.consumePending {
            if (it == "first") firstRead.await()
            imported += it
        } }
        runCurrent()
        pending.value = "second"
        firstRead.complete(Unit)
        runCurrent()
        assertEquals(listOf("first", "second"), imported)
        assertNull(pending.value)
    }

    @Test fun cancellingAReadLeavesItsEventAvailableForAnotherCollector() = runTest {
        val pending = MutableStateFlow<String?>("shared package")
        val read = CompletableDeferred<Unit>()
        val consumer = backgroundScope.launch { pending.consumePending { read.await() } }
        runCurrent()
        consumer.cancelAndJoin()
        assertEquals("shared package", pending.value)
        val imported = mutableListOf<String>()
        backgroundScope.launch { pending.consumePending { imported += it } }
        runCurrent()
        assertEquals(listOf("shared package"), imported)
        assertNull(pending.value)
    }
}
