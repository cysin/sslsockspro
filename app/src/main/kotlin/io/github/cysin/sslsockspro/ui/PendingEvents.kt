package io.github.cysin.sslsockspro.ui

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull

/** Collect from a stable effect, and acknowledge only after reading the event.
 * Clearing an effect's own key before a suspended read cancels that read.
 * A newer event must also survive completion of the previous one. */
internal suspend fun <T : Any> MutableStateFlow<T?>.consumePending(action: suspend (T) -> Unit) {
    filterNotNull().collect { event ->
        action(event)
        compareAndSet(event, null)
    }
}
