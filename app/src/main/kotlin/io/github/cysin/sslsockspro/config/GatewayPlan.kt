package io.github.cysin.sslsockspro.config

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Gateway addresses resolved on the physical network before native engines
 * start. Each hostname keeps several addresses so stunnel and OpenVPN can fail
 * over without another bootstrap lookup; only these peers may be connected. */
@Serializable
data class GatewayPlan(val hosts: Map<String, List<String>>, val allowed: List<String>) {
    fun encode(): String = codec.encodeToString(this)

    companion object {
        const val MAX_ADDRESSES = 4
        private val codec = Json { ignoreUnknownKeys = false }

        fun decode(text: String): GatewayPlan = codec.decodeFromString<GatewayPlan>(text)

        /** [resolve] returns addresses in the platform's preferred order. */
        fun create(endpoints: List<Endpoint>, resolve: (String) -> List<String>): GatewayPlan {
            require(endpoints.isNotEmpty()) { "Profile has no gateway endpoint" }
            val hosts = endpoints.map { it.host }.distinct().associateWith { host ->
                resolve(host).map { it.substringBefore('%') }.distinct().take(MAX_ADDRESSES).also {
                    require(it.isNotEmpty()) { "Gateway hostname could not be resolved" }
                }
            }
            val allowed = endpoints.flatMap { endpoint -> hosts.getValue(endpoint.host).map { "$it|${endpoint.port}" } }.distinct()
            return GatewayPlan(hosts, allowed)
        }
    }
}
