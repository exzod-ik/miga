package org.miga.core

import java.net.IDN
import java.util.Locale

data class DomainRule(val id: String, val profileId: String, val pattern: String)

object DomainNames {
    fun normalize(input: String): String {
        val value = input.trim().removeSuffix(".")
        require(value.isNotEmpty() && value.length <= 253 && !value.endsWith('.')) { "Invalid domain" }
        val ascii = try { IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT) }
        catch (_: IllegalArgumentException) { throw IllegalArgumentException("Invalid domain") }
        require(ascii.length <= 253 && ascii.split('.').size >= 2 &&
            ascii.split('.').all { it.isNotEmpty() && it.length <= 63 }) { "Invalid domain" }
        return ascii
    }

    fun pattern(input: String): String = if (input.trim().startsWith("*."))
        "*.${normalize(input.trim().substring(2))}" else normalize(input)

    fun matches(pattern: String, domain: String): Boolean {
        val name = normalize(domain)
        return if (pattern.startsWith("*.")) {
            val suffix = pattern.substring(2)
            name == suffix || name.endsWith(".$suffix")
        } else name == pattern
    }
}

class DomainRuleSet(rules: List<DomainRule>) {
    private val rows = rules.toList()
    fun isNotEmpty(): Boolean = rows.isNotEmpty()

    init {
        require(rows.map { it.id }.toSet().size == rows.size) { "Duplicate domain rule ID" }
        require(rows.all { DomainNames.pattern(it.pattern) == it.pattern }) { "Noncanonical domain rule" }
        for (i in rows.indices) for (j in i + 1 until rows.size) {
            val a = rows[i]; val b = rows[j]
            require(a.pattern != b.pattern) { "Duplicate domain rule" }
            if (a.profileId != b.profileId) require(!overlap(a.pattern, b.pattern)) {
                "Domain rules for different profiles overlap"
            }
        }
    }

    fun profileFor(domain: String): String? = rows.firstOrNull { DomainNames.matches(it.pattern, domain) }?.profileId

    private fun overlap(a: String, b: String): Boolean {
        val aw = a.startsWith("*."); val bw = b.startsWith("*.")
        val an = a.removePrefix("*."); val bn = b.removePrefix("*.")
        return when {
            aw && bw -> an == bn || an.endsWith(".$bn") || bn.endsWith(".$an")
            aw -> bn == an || bn.endsWith(".$an")
            bw -> an == bn || an.endsWith(".$bn")
            else -> an == bn
        }
    }
}
