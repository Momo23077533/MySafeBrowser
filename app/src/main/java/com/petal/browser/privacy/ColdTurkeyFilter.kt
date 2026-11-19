package com.petal.browser.privacy

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.URLDecoder
import java.util.Locale

/**
 * ColdTurkeyFilter
 * -------------------------------------------------------------------------
 * Deterministic 3-tier Cold Turkey URL & Window Title filter engine.
 * Rules are loaded from immutable APK assets so clearing Android App Data
 * cannot delete or weaken the blocklist.
 *
 * 3-Tier Precedence:
 *   Tier 1 (Hard Keyword / Search Wildcards): Evaluated FIRST. Never overridden
 *          by broad domain allowlist rules (e.g. google.com).
 *   Tier 2 (Allowlist / Exceptions): @@-prefixed rules or allowed.txt entries.
 *          If Tier 1 passes and Tier 2 matches, ALLOW.
 *   Tier 3 (Blocked Domains & Patterns): Domain rules (matching apex + subdomains
 *          + all subpaths) and host/pattern wildcards. If matched, BLOCK.
 */
class ColdTurkeyFilter private constructor(
    private val tier1KeywordWildcards: List<CompiledWildcard>,
    private val tier1TitleWildcards: List<CompiledWildcard>,
    private val tier2AllowDomains: Set<String>,
    private val tier2AllowPathRules: List<PathRule>,
    private val tier2AllowWildcards: List<CompiledWildcard>,
    private val tier3BlockDomains: Set<String>,
    private val tier3BlockPathRules: List<PathRule>,
    private val tier3BlockSchemes: Set<String>,
    private val tier3BlockWildcards: List<CompiledWildcard>,
    val totalRuleLines: Int
) {

    data class CompiledWildcard(
        val raw: String,
        val regex: Regex
    )

    data class PathRule(
        val host: String,
        val pathPrefix: String
    )

    /**
     * Checks whether a URL uses a dangerous internal bypass scheme that must be denied.
     * Blocks ALL about:* URLs except about:blank (and internal about:home), plus
     * view-source:, data:text/html, and arbitrary file:// URLs.
     */
    fun isDangerousScheme(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        val trimmed = url.trim()
        val lower = trimmed.lowercase(Locale.ROOT)

        // Always allow our own packaged block page
        if (isBlockedPageUrl(lower)) return false

        if (lower.startsWith("about:")) {
            return lower != "about:blank" && lower != "about:home"
        }
        if (lower.startsWith("view-source:")) return true
        if (lower.startsWith("data:text/html")) return true
        if (lower.startsWith("file://")) return true
        return false
    }

    /**
     * Evaluates [url] through the 3-tier Cold Turkey engine against BOTH the raw
     * lowercased URL and the UTF-8 decoded normalized URL (supporting English and
     * percent-encoded Arabic queries).
     */
    fun shouldBlockUrl(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        val trimmed = url.trim()
        val rawLower = trimmed.lowercase(Locale.ROOT)

        if (rawLower == "about:blank" || rawLower == "about:home" || isBlockedPageUrl(rawLower)) {
            return false
        }

        val decodedLower = normalizeAndDecode(trimmed)
        val host = extractHost(rawLower)

        // Tier 1: Hard Keyword / Search Wildcards (NEVER overridden by allowlist)
        if (matchesWildcards(tier1KeywordWildcards, rawLower, decodedLower)) {
            return true
        }

        // Tier 2: Allowlist / Exceptions
        if (matchesAllowlist(host, rawLower, decodedLower)) {
            return false
        }

        // Tier 3: Blocked Schemes, Domains, Path Rules & Host Wildcards
        if (tier3BlockSchemes.any { rawLower.startsWith(it) || decodedLower.startsWith(it) }) {
            return true
        }

        if (host.isNotEmpty() && matchesDomainSet(host, tier3BlockDomains)) {
            return true
        }

        if (host.isNotEmpty() && matchesPathRules(host, rawLower, decodedLower, tier3BlockPathRules)) {
            return true
        }

        if (matchesWildcards(tier3BlockWildcards, rawLower, decodedLower)) {
            return true
        }

        return false
    }

    /**
     * Cold Turkey Window Title blocking: checks updated page titles against Tier 1
     * keyword wildcards.
     */
    fun shouldBlockTitle(title: String?): Boolean {
        if (title.isNullOrBlank()) return false
        val rawLower = title.trim().lowercase(Locale.ROOT)
        if (rawLower.isEmpty()) return false
        val decodedLower = normalizeAndDecode(title)
        return matchesWildcards(tier1TitleWildcards, rawLower, decodedLower)
    }

    /**
     * Secondary SafeSearch enforcement for Google Search and Bing Search URLs.
     * Returns a rewritten URL with safe=active / adlt=strict if missing, or null if already compliant.
     */
    fun enforceSafeSearchUrl(url: String?): String? {
        if (url.isNullOrBlank()) return null
        val lower = url.lowercase(Locale.ROOT)
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) return null

        val host = extractHost(lower)
        val path = extractPath(lower)

        val isGoogleSearch = (host == "google.com" || host.endsWith(".google.com") || host.contains(".google.") || host.startsWith("google.")) &&
            (path == "/search" || path.startsWith("/search/"))
        if (isGoogleSearch) {
            if (!Regex("""([?&])safe=active(&|$)""").containsMatchIn(lower)) {
                val sep = if (url.contains("?")) "&" else "?"
                return "${url}${sep}safe=active"
            }
            return null
        }

        val isBingSearch = (host == "bing.com" || host.endsWith(".bing.com")) &&
            (path == "/search" || path.startsWith("/search/"))
        if (isBingSearch) {
            if (!Regex("""([?&])adlt=strict(&|$)""").containsMatchIn(lower)) {
                val sep = if (url.contains("?")) "&" else "?"
                return "${url}${sep}adlt=strict"
            }
            return null
        }

        return null
    }

    private fun matchesAllowlist(host: String, rawLower: String, decodedLower: String): Boolean {
        if (host.isNotEmpty() && matchesDomainSet(host, tier2AllowDomains)) return true
        if (host.isNotEmpty() && matchesPathRules(host, rawLower, decodedLower, tier2AllowPathRules)) return true
        if (matchesWildcards(tier2AllowWildcards, rawLower, decodedLower)) return true
        return false
    }

    private fun matchesWildcards(rules: List<CompiledWildcard>, rawLower: String, decodedLower: String): Boolean {
        for (rule in rules) {
            if (rule.regex.containsMatchIn(rawLower)) return true
            if (decodedLower != rawLower && rule.regex.containsMatchIn(decodedLower)) return true
        }
        return false
    }

    private fun matchesDomainSet(host: String, domains: Set<String>): Boolean {
        if (domains.isEmpty()) return false
        var candidate = host
        while (candidate.isNotEmpty()) {
            if (domains.contains(candidate)) return true
            val dot = candidate.indexOf('.')
            if (dot < 0 || dot == candidate.length - 1) break
            candidate = candidate.substring(dot + 1)
        }
        return false
    }

    private fun matchesPathRules(
        host: String,
        rawLower: String,
        decodedLower: String,
        rules: List<PathRule>
    ): Boolean {
        if (rules.isEmpty()) return false
        val rawPath = extractPathAndQuery(rawLower)
        val decPath = extractPathAndQuery(decodedLower)
        for (r in rules) {
            if (host == r.host || host.endsWith(".${r.host}")) {
                if (rawPath.startsWith(r.pathPrefix) || decPath.startsWith(r.pathPrefix)) {
                    return true
                }
            }
        }
        return false
    }

    companion object {
        private const val TAG = "ColdTurkeyFilter"
        const val RULES_ASSET_DIR = "web_extensions/petal_network_blocker/rules"
        const val BLOCKED_PAGE_URI = "resource://android/assets/web_extensions/petal_network_blocker/blocked.html"

        @Volatile
        private var instance: ColdTurkeyFilter? = null

        @JvmStatic
        fun isBlockedPageUrl(lowerUrl: String): Boolean {
            return lowerUrl.startsWith(BLOCKED_PAGE_URI) ||
                (lowerUrl.startsWith("moz-extension://") && lowerUrl.contains("/blocked.html"))
        }

        @JvmStatic
        fun getInstance(context: Context): ColdTurkeyFilter {
            instance?.let { return it }
            return synchronized(this) {
                instance ?: loadFromAssets(context.applicationContext).also { instance = it }
            }
        }

        @JvmStatic
        fun loadFromAssets(context: Context): ColdTurkeyFilter {
            val blockLines = mutableListOf<String>()
            val allowLines = mutableListOf<String>()
            try {
                val assetManager = context.assets
                val files = assetManager.list(RULES_ASSET_DIR)?.sorted() ?: emptyList()
                for (name in files) {
                    if (!name.endsWith(".txt", ignoreCase = true) && !name.endsWith(".ctbl", ignoreCase = true)) {
                        continue
                    }
                    val isAllowFile = name.equals("allowed.txt", ignoreCase = true) ||
                        name.contains("allow", ignoreCase = true)
                    assetManager.open("$RULES_ASSET_DIR/$name").use { stream ->
                        BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { reader ->
                            reader.forEachLine { line ->
                                if (isAllowFile) allowLines.add(line) else blockLines.add(line)
                            }
                        }
                    }
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Failed to load Cold Turkey rules from assets: ${t.message}", t)
            }
            return fromRuleLines(blockLines, allowLines)
        }

        @JvmStatic
        fun fromRuleLines(
            blockLines: List<String>,
            allowLines: List<String> = emptyList()
        ): ColdTurkeyFilter {
            val tier1Keywords = mutableListOf<CompiledWildcard>()
            val tier1Titles = mutableListOf<CompiledWildcard>()
            val tier2Domains = HashSet<String>()
            val tier2Paths = mutableListOf<PathRule>()
            val tier2Wildcards = mutableListOf<CompiledWildcard>()
            val tier3Domains = HashSet<String>()
            val tier3Paths = mutableListOf<PathRule>()
            val tier3Schemes = HashSet<String>()
            val tier3Wildcards = mutableListOf<CompiledWildcard>()

            var count = 0

            fun parseAllowRule(raw: String) {
                val clean = raw.trim()
                if (clean.isEmpty() || clean.startsWith("#")) return
                val lower = clean.lowercase(Locale.ROOT)
                if (lower.startsWith("*.")) {
                    val base = lower.removePrefix("*.")
                    if (!base.contains("*") && !base.contains("/")) {
                        tier2Domains.add(base)
                        return
                    }
                }
                if (lower.contains("*")) {
                    compileWildcard(lower)?.let { tier2Wildcards.add(it) }
                } else if (lower.contains("/")) {
                    val idx = lower.indexOf('/')
                    val host = lower.substring(0, idx).removePrefix("www.")
                    val path = lower.substring(idx)
                    if (host.isNotEmpty()) tier2Paths.add(PathRule(host, path))
                } else {
                    tier2Domains.add(lower.removePrefix("www."))
                }
            }

            for (line in allowLines) {
                parseAllowRule(line)
            }

            for (rawLine in blockLines) {
                val trimmed = rawLine.trim()
                if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
                count++

                if (trimmed.startsWith("@@")) {
                    parseAllowRule(trimmed.substring(2))
                    continue
                }

                val lower = trimmed.lowercase(Locale.ROOT)

                // Pure subdomain wildcard *.example.com -> Tier 3 domain rule (matches example.com and *.example.com)
                if (lower.startsWith("*.") && !lower.substring(2).contains("*") && !lower.contains("/") && !lower.contains("?")) {
                    val domain = lower.substring(2).removePrefix("www.")
                    if (domain.isNotEmpty()) {
                        tier3Domains.add(domain)
                        continue
                    }
                }

                // Scheme rule without wildcard (e.g., javascript:, extension://...)
                if (!lower.contains("*") && (lower.endsWith(":") || lower.contains("://"))) {
                    tier3Schemes.add(lower)
                    continue
                }

                // Wildcard rules
                if (lower.contains("*")) {
                    val compiled = compileWildcard(lower) ?: continue
                    if (isHostOnlyWildcard(lower)) {
                        tier3Wildcards.add(compiled)
                    } else {
                        tier1Keywords.add(compiled)
                        if (isTitleEligibleWildcard(lower)) {
                            tier1Titles.add(compiled)
                        }
                    }
                    continue
                }

                // Plain domain + path rule (e.g., youtube.com/shorts, web.telegram.org/a)
                if (lower.contains("/")) {
                    val idx = lower.indexOf('/')
                    val host = lower.substring(0, idx).removePrefix("www.")
                    val path = lower.substring(idx)
                    if (host.isNotEmpty()) {
                        tier3Paths.add(PathRule(host, path))
                    }
                    continue
                }

                // Plain domain rule (e.g., example.com)
                if (lower.contains(".")) {
                    tier3Domains.add(lower.removePrefix("www."))
                } else {
                    // Fallback literal substring/query pattern
                    compileWildcard("*$lower*")?.let { tier1Keywords.add(it) }
                }
            }

            return ColdTurkeyFilter(
                tier1KeywordWildcards = tier1Keywords,
                tier1TitleWildcards = tier1Titles,
                tier2AllowDomains = tier2Domains,
                tier2AllowPathRules = tier2Paths,
                tier2AllowWildcards = tier2Wildcards,
                tier3BlockDomains = tier3Domains,
                tier3BlockPathRules = tier3Paths,
                tier3BlockSchemes = tier3Schemes,
                tier3BlockWildcards = tier3Wildcards,
                totalRuleLines = count
            )
        }

        // Host-only wildcards (e.g. "proxy.*", "croxy.*", "fast*vpn*") belong to Tier 3.
        // Keyword/search/path wildcards belong to Tier 1 so they are never overridden by broad domain allowlists.
        private fun isHostOnlyWildcard(lowerRule: String): Boolean {
            if (lowerRule.startsWith("*")) return false
            if (lowerRule.contains("/") || lowerRule.contains("?") || lowerRule.contains(":")) return false
            return true
        }

        /**
         * Window title blocking applies to Tier 1 keyword wildcards (e.g. *keyword*)
         * that do not look like URL paths, query templates, or domain-only patterns.
         */
        private fun isTitleEligibleWildcard(lowerRule: String): Boolean {
            if (!lowerRule.startsWith("*") || !lowerRule.endsWith("*")) return false
            val inner = lowerRule.substring(1, lowerRule.length - 1).trim()
            if (inner.length < 3) return false
            if (inner.contains("/") || inner.contains("?") || inner.contains(":")) return false
            if (inner.contains(".") && !inner.contains(" ")) return false
            return true
        }

        private fun compileWildcard(lowerRule: String): CompiledWildcard? {
            return try {
                val sb = StringBuilder()
                for (ch in lowerRule) {
                    when (ch) {
                        '*' -> sb.append(".*")
                        '.', '+', '?', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\' -> {
                            sb.append('\\').append(ch)
                        }
                        else -> sb.append(ch)
                    }
                }
                CompiledWildcard(lowerRule, Regex(sb.toString(), RegexOption.IGNORE_CASE))
            } catch (_: Throwable) {
                null
            }
        }

        /**
         * Safe UTF-8 URL normalization:
         * 1. Replaces '+' with space
         * 2. Safely decodes percent-encoded UTF-8 sequences (never crashes on malformed '%')
         * 3. Lowercases for case-insensitive matching
         */
        @JvmStatic
        fun normalizeAndDecode(input: String): String {
            val plusReplaced = input.replace('+', ' ')
            var current = plusReplaced
            for (pass in 0 until 2) {
                val decoded = safePercentDecode(current)
                if (decoded == current) break
                current = decoded
            }
            return current.lowercase(Locale.ROOT)
        }

        private fun safePercentDecode(s: String): String {
            return try {
                URLDecoder.decode(s, "UTF-8")
            } catch (_: Throwable) {
                // Segment-safe fallback so one malformed % sequence never prevents decoding valid %D8%... Arabic bytes
                val sb = StringBuilder(s.length)
                var i = 0
                while (i < s.length) {
                    if (s[i] == '%') {
                        var j = i
                        while (j + 2 < s.length && s[j] == '%' && isHex(s[j + 1]) && isHex(s[j + 2])) {
                            j += 3
                        }
                        if (j > i) {
                            val chunk = s.substring(i, j)
                            val decodedChunk = try {
                                URLDecoder.decode(chunk, "UTF-8")
                            } catch (_: Throwable) {
                                chunk
                            }
                            sb.append(decodedChunk)
                            i = j
                            continue
                        }
                    }
                    sb.append(s[i])
                    i++
                }
                sb.toString()
            }
        }

        private fun isHex(c: Char): Boolean {
            return (c in '0'..'9') || (c in 'a'..'f') || (c in 'A'..'F')
        }

        private fun extractHost(lowerUrl: String): String {
            return try {
                val uri = Uri.parse(lowerUrl)
                val h = uri.host
                if (!h.isNullOrBlank()) {
                    h.lowercase(Locale.ROOT).removePrefix("www.")
                } else {
                    extractHostFallback(lowerUrl)
                }
            } catch (_: Throwable) {
                extractHostFallback(lowerUrl)
            }
        }

        private fun extractHostFallback(lowerUrl: String): String {
            val schemeIdx = lowerUrl.indexOf("://")
            val start = if (schemeIdx >= 0) schemeIdx + 3 else return ""
            var end = lowerUrl.length
            for (sep in charArrayOf('/', '?', '#', ':')) {
                val idx = lowerUrl.indexOf(sep, start)
                if (idx in start until end) end = idx
            }
            val authority = lowerUrl.substring(start, end)
            val atIdx = authority.lastIndexOf('@')
            val host = if (atIdx >= 0) authority.substring(atIdx + 1) else authority
            return host.removePrefix("www.")
        }

        private fun extractPath(lowerUrl: String): String {
            val schemeIdx = lowerUrl.indexOf("://")
            val start = if (schemeIdx >= 0) schemeIdx + 3 else 0
            val slashIdx = lowerUrl.indexOf('/', start)
            if (slashIdx < 0) return "/"
            val qIdx = lowerUrl.indexOf('?', slashIdx)
            val hIdx = lowerUrl.indexOf('#', slashIdx)
            val end = listOf(qIdx, hIdx, lowerUrl.length).filter { it >= 0 }.minOrNull() ?: lowerUrl.length
            return lowerUrl.substring(slashIdx, end)
        }

        private fun extractPathAndQuery(lowerUrl: String): String {
            val schemeIdx = lowerUrl.indexOf("://")
            val start = if (schemeIdx >= 0) schemeIdx + 3 else 0
            val slashIdx = lowerUrl.indexOf('/', start)
            if (slashIdx < 0) return "/"
            val hIdx = lowerUrl.indexOf('#', slashIdx)
            val end = if (hIdx >= 0) hIdx else lowerUrl.length
            return lowerUrl.substring(slashIdx, end)
        }
    }
}
