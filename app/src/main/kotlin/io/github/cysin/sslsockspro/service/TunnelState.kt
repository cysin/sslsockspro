package io.github.cysin.sslsockspro.service

import io.github.cysin.sslsockspro.model.ConnectionStatus
import io.github.cysin.sslsockspro.privacy.Redactor
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import java.time.Instant

object TunnelState {
    private val statusMutable = MutableStateFlow(ConnectionStatus())
    val status = statusMutable.asStateFlow()
    private val activityMutable = MutableStateFlow(ConnectionStatus())
    /** [status] without traffic counters; it changes only with the connection
     * itself, so screens that ignore counters are not recomposed by them. */
    val activity = activityMutable.asStateFlow()
    private val uiVisibleMutable = MutableStateFlow(false)
    /** Whether an app screen is in the foreground. */
    val uiVisible = uiVisibleMutable.asStateFlow()
    fun uiVisible(value: Boolean) { uiVisibleMutable.value = value }
    private val noticeMutable = MutableStateFlow<String?>(null)
    /** Information about the current connection, such as a detected backend. */
    val notice = noticeMutable.asStateFlow()
    fun notice(value: String?) { noticeMutable.value = value?.let(Redactor::redactIdentifiers) }
    private val testRequestsMutable = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val testRequests = testRequestsMutable.asSharedFlow()
    private val testResultMutable = MutableStateFlow<String?>(null)
    val testResult = testResultMutable.asStateFlow()
    fun requestTest() { testResultMutable.value = "Testing…"; testRequestsMutable.tryEmit(Unit) }
    fun testResult(value: String?) { testResultMutable.value = value }
    /** An OpenVPN server's request for a code, such as a one-time password. */
    data class Challenge(val text: String, val echo: Boolean)
    private val challengeMutable = MutableStateFlow<Challenge?>(null)
    val challenge = challengeMutable.asStateFlow()
    fun challenge(value: Challenge?) { challengeMutable.value = value }
    private val challengeAnswersMutable = MutableSharedFlow<String>(extraBufferCapacity = 1)
    /** Answers stay in memory and go only to the worker. */
    val challengeAnswers = challengeAnswersMutable.asSharedFlow()
    fun answerChallenge(response: String) { challengeMutable.value = null; challengeAnswersMutable.tryEmit(response) }
    private val logsMutable = MutableStateFlow<List<String>>(emptyList())
    val logs = logsMutable.asStateFlow()
    @Synchronized fun status(value: ConnectionStatus) {
        statusMutable.value = value
        activityMutable.value = value.copy(bytesSent = 0, bytesReceived = 0)
    }
    /** Every diagnostic, from the UI, the owner or native engines, is
     * redacted here before it is stored, displayed or exported. */
    @Synchronized fun log(message: String) {
        val redacted = Redactor.redact(message).take(1024)
        logsMutable.value = (logsMutable.value.takeLast(499) + "${Instant.now()} $redacted")
    }
    @Synchronized fun clearLogs() { logsMutable.value = emptyList() }
}
