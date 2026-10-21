package io.github.cysin.sslsockspro.network

import org.xbill.DNS.AAAARecord
import org.xbill.DNS.ARecord
import org.xbill.DNS.DClass
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.Flags
import org.xbill.DNS.Message
import org.xbill.DNS.Opcode
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.SOARecord
import org.xbill.DNS.Section
import org.xbill.DNS.Type
import java.net.InetAddress
import java.util.Locale
import java.util.concurrent.TimeUnit

/** DNS for routed apps. Answers what needs no network locally (AAAA when
 * IPv6 is blocked, cached answers, synthetic addresses) and sends the rest as
 * DNS-over-HTTPS through the tunnel. Nothing ever leaves outside the tunnel. */
class DnsService(
    private val upstream: (ByteArray, (ByteArray) -> Unit) -> Unit,
    private val cache: DnsCache,
    private val synthetic: FakeDns?,
    private val ipv6: Boolean,
) : DnsHandler {
    override fun resolve(query: ByteArray, reply: (ByteArray) -> Unit) {
        val message = runCatching { Message(query) }.getOrNull()
        val question = message?.question
        if (message == null || question == null || message.header.opcode != Opcode.QUERY || message.header.getFlag(Flags.QR.toInt())) {
            reply(TunneledDns.failure(query)); return
        }
        if (question.dClass == DClass.IN) {
            // Android blocks IPv6 in this VPN; asking upstream would only add a round trip.
            if (question.type == Type.AAAA && !ipv6) { reply(TunneledDns.response(message, Rcode.NOERROR).toWire()); return }
            synthetic?.let { names ->
                when (question.type) {
                    Type.A, Type.AAAA -> names.answer(message)?.let { reply(it); return }
                    // Service bindings would carry real address hints.
                    Type.HTTPS, Type.SVCB -> { reply(TunneledDns.response(message, Rcode.NOERROR).toWire()); return }
                }
            }
        }
        cache.lookup(message)?.let { reply(it); return }
        upstream(query) { response -> cache.store(message, response); reply(response) }
    }
}

/** Positive answers live for their TTL (at most an hour); negative answers
 * for at most 30 seconds. Served answers carry the remaining TTL. */
class DnsCache(private val capacity: Int = 4096, private val clock: () -> Long = System::nanoTime) {
    private data class Key(val name: String, val type: Int, val dclass: Int, val dnssec: Boolean, val checking: Boolean)
    private class Entry(val answer: ByteArray, val stored: Long, val expires: Long)
    private val entries = object : LinkedHashMap<Key, Entry>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, Entry>?) = size > capacity
    }

    private fun key(query: Message): Key? {
        val question = query.question ?: return null
        return Key(question.name.toString().lowercase(Locale.ROOT), question.type, question.dClass,
            (query.opt?.flags ?: 0) and ExtendedFlags.DO != 0, query.header.getFlag(Flags.CD.toInt()))
    }

    @Synchronized fun lookup(query: Message): ByteArray? {
        val key = key(query) ?: return null
        val entry = entries[key] ?: return null
        val now = clock()
        if (now >= entry.expires) { entries.remove(key); return null }
        val elapsed = TimeUnit.NANOSECONDS.toSeconds(now - entry.stored)
        val answer = Message(entry.answer)
        answer.header.id = query.header.id
        if (query.header.getFlag(Flags.RD.toInt())) answer.header.setFlag(Flags.RD.toInt()) else answer.header.unsetFlag(Flags.RD.toInt())
        for (section in listOf(Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL)) {
            val records = answer.getSection(section)
            answer.removeAllRecords(section)
            records.forEach { answer.addRecord(Record.newRecord(it.name, it.type, it.dClass, maxOf(0, it.ttl - elapsed), it.rdataToWireCanonical()), section) }
        }
        return answer.toWire()
    }

    @Synchronized fun store(query: Message, response: ByteArray) {
        val key = key(query) ?: return
        val answer = runCatching { Message(response) }.getOrNull() ?: return
        if (answer.header.getFlag(Flags.TC.toInt()) || answer.question != query.question) return
        val ttl = when (answer.rcode) {
            Rcode.NOERROR -> answer.getSection(Section.ANSWER).minOfOrNull { it.ttl } ?: negative(answer)
            Rcode.NXDOMAIN -> negative(answer)
            else -> return
        }.coerceAtMost(MAX_TTL)
        if (ttl <= 0) return
        val now = clock()
        entries[key] = Entry(response, now, now + TimeUnit.SECONDS.toNanos(ttl))
    }

    private fun negative(answer: Message): Long =
        (answer.getSection(Section.AUTHORITY).filterIsInstance<SOARecord>().firstOrNull()?.let { minOf(it.ttl, it.minimum) } ?: NEGATIVE_TTL)
            .coerceAtMost(NEGATIVE_TTL)

    @Synchronized fun clear() = entries.clear()

    companion object {
        private const val MAX_TTL = 3600L
        private const val NEGATIVE_TTL = 30L
    }
}

/** Proxy-side name resolution. Address queries get synthetic addresses
 * (198.18.128.0/17 and fd00:5353:1::/64) and the relay sends the original
 * name to the proxy, so no third-party resolver sees the user's lookups.
 * Mappings survive reconnects of the same profile and age out least
 * recently used when the range is exhausted. */
class FakeDns(private val capacity: Int = 32766, private val clock: () -> Long = System::nanoTime) {
    private class Mapping(val name: String, var used: Long)
    private val indexes = HashMap<String, Int>()
    private val mappings = HashMap<Int, Mapping>()
    private var cursor = 0

    /** Null when the name should not be synthesized and needs real DNS. */
    @Synchronized fun answer(query: Message): ByteArray? {
        val question = query.question
        val name = question.name.toString(true).lowercase(Locale.ROOT)
        if (!eligible(name)) return null
        val index = index(name)
        val record = if (question.type == Type.A) ARecord(question.name, DClass.IN, TTL, InetAddress.getByAddress(ipv4(index)))
            else AAAARecord(question.name, DClass.IN, TTL, InetAddress.getByAddress(ipv6(index)))
        return TunneledDns.response(query, Rcode.NOERROR).apply { addRecord(record, Section.ANSWER) }.toWire()
    }

    /** The name to request upstream for [address]; other addresses pass
     * through. An address in the synthetic range with no mapping fails. */
    @Synchronized fun target(address: String): String {
        val index = indexOf(address) ?: return address
        val mapping = mappings[index] ?: throw IllegalArgumentException("Unknown synthetic address")
        mapping.used = clock()
        return mapping.name
    }

    @Synchronized fun clear() { indexes.clear(); mappings.clear(); cursor = 0 }

    private fun eligible(name: String): Boolean =
        name.contains('.') && NAME.matches(name) && name != "localhost" &&
            listOf(".localhost", ".local", ".arpa").none { name.endsWith(it) }

    private fun index(name: String): Int {
        indexes[name]?.let { index -> mappings.getValue(index).used = clock(); return index }
        val index = if (mappings.size < capacity) {
            while (cursor in mappings) cursor = (cursor + 1) % capacity
            cursor.also { cursor = (cursor + 1) % capacity }
        } else mappings.minByOrNull { it.value.used }!!.key.also { indexes.remove(mappings.getValue(it).name) }
        indexes[name] = index
        mappings[index] = Mapping(name, clock())
        return index
    }

    private fun ipv4(index: Int): ByteArray {
        val value = V4_BASE + index + 1
        return byteArrayOf((value shr 24).toByte(), (value shr 16).toByte(), (value shr 8).toByte(), value.toByte())
    }

    private fun ipv6(index: Int): ByteArray = V6_PREFIX.copyOf(16).also { bytes ->
        val value = index + 1
        bytes[12] = (value shr 24).toByte(); bytes[13] = (value shr 16).toByte(); bytes[14] = (value shr 8).toByte(); bytes[15] = value.toByte()
    }

    private fun indexOf(address: String): Int? {
        val bytes = runCatching { if (address.contains(':') || IPV4.matches(address)) InetAddress.getByName(address).address else null }.getOrNull() ?: return null
        return when (bytes.size) {
            4 -> {
                val value = ((bytes[0].toInt() and 255) shl 24) or ((bytes[1].toInt() and 255) shl 16) or ((bytes[2].toInt() and 255) shl 8) or (bytes[3].toInt() and 255)
                if (value and V4_MASK != V4_BASE) null else (value - V4_BASE - 1).takeIf { it in 0 until capacity } ?: -1
            }
            16 -> if (!bytes.copyOf(8).contentEquals(V6_PREFIX.copyOf(8))) null else {
                val value = ((bytes[12].toInt() and 255) shl 24) or ((bytes[13].toInt() and 255) shl 16) or ((bytes[14].toInt() and 255) shl 8) or (bytes[15].toInt() and 255)
                (value - 1).takeIf { it in 0 until capacity } ?: -1
            }
            else -> null
        }
    }

    companion object {
        private const val TTL = 60L
        private const val V4_BASE = (198 shl 24) or (18 shl 16) or (128 shl 8)
        private const val V4_MASK = -0x8000 // 255.255.128.0
        private val V6_PREFIX = byteArrayOf(0xfd.toByte(), 0, 0x53, 0x53, 0, 1, 0, 0)
        private val NAME = Regex("[a-z0-9_]([a-z0-9_-]{0,62}\\.)*[a-z0-9_-]{1,63}\\.?")
        private val IPV4 = Regex("(?:\\d{1,3}\\.){3}\\d{1,3}")
    }
}
