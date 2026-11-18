package com.petal.browser.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.URLEncoder

class ColdTurkeyFilterTest {

    private fun loadPackagedRules(): List<String> {
        val candidates = listOf(
            File("src/main/assets/web_extensions/petal_network_blocker/rules/Tofan websites.txt"),
            File("app/src/main/assets/web_extensions/petal_network_blocker/rules/Tofan websites.txt")
        )
        val file = candidates.firstOrNull { it.exists() }
            ?: throw IllegalStateException("Packaged Cold Turkey rules file not found")
        return file.readLines(Charsets.UTF_8)
    }

    @Test
    fun packagedRulesLoadedWithoutTruncation() {
        val lines = loadPackagedRules()
        val filter = ColdTurkeyFilter.fromRuleLines(lines)
        assertEquals(2375, lines.size)
        assertEquals(2375, filter.totalRuleLines)
    }

    @Test
    fun blocksDomainsAndSubdomains() {
        val filter = ColdTurkeyFilter.fromRuleLines(loadPackagedRules())
        assertTrue(filter.shouldBlockUrl("https://duckduckgo.com/"))
        assertTrue(filter.shouldBlockUrl("https://sub.duckduckgo.com/search?q=hello"))
        assertTrue(filter.shouldBlockUrl("https://croxyproxy.com/proxy"))
        assertTrue(filter.shouldBlockUrl("https://m.youtube.com/shorts/abc123"))
    }

    @Test
    fun tier1OverridesBroadDomainAllowlistForEnglishAndArabicPercentEncodedQueries() {
        val lines = loadPackagedRules()
        val filter = ColdTurkeyFilter.fromRuleLines(
            blockLines = lines,
            allowLines = listOf("google.com")
        )

        // Legitimate Google search passes
        assertFalse(filter.shouldBlockUrl("https://www.google.com/search?safe=active&q=android+development"))

        // English blocked wildcard inside allowed google.com is BLOCKED by Tier 1
        assertTrue(filter.shouldBlockUrl("https://www.google.com/search?q=free+vpn+download"))
        assertTrue(filter.shouldBlockUrl("https://www.google.com/search?q=web%20proxy%20site"))

        // Percent-encoded Arabic blocked wildcard inside allowed google.com is BLOCKED by Tier 1
        val arabicKeyword = "\u0628\u0631\u0648\u0643\u0633\u064A" // بروكسي (proxy)
        val encodedArabic = URLEncoder.encode(arabicKeyword, "UTF-8")
        assertTrue(encodedArabic.contains("%D8%"))
        assertTrue(filter.shouldBlockUrl("https://www.google.com/search?q=$encodedArabic"))
    }

    @Test
    fun allowsLegitimateSitesAndBlockPage() {
        val filter = ColdTurkeyFilter.fromRuleLines(loadPackagedRules())
        assertFalse(filter.shouldBlockUrl("https://www.wikipedia.org/wiki/Android"))
        assertFalse(filter.shouldBlockUrl("https://developer.android.com/guide"))
        assertFalse(filter.shouldBlockUrl("https://www.youtube.com/watch?v=dQw4w9WgXcQ"))
        assertFalse(filter.shouldBlockUrl("about:blank"))
        assertFalse(filter.shouldBlockUrl(ColdTurkeyFilter.BLOCKED_PAGE_URI))
    }

    @Test
    fun malformedPercentEncodingDoesNotCrash() {
        val filter = ColdTurkeyFilter.fromRuleLines(loadPackagedRules())
        assertFalse(filter.shouldBlockUrl("https://www.wikipedia.org/wiki/100%_test_%E0%A4%A_%ZZ"))
        val encodedArabic = URLEncoder.encode("\u0628\u0631\u0648\u0643\u0633\u064A", "UTF-8")
        assertTrue(filter.shouldBlockUrl("https://www.google.com/search?q=%ZZ+$encodedArabic"))
    }

    @Test
    fun blocksDangerousInternalSchemes() {
        val filter = ColdTurkeyFilter.fromRuleLines(emptyList())
        assertTrue(filter.isDangerousScheme("about:config"))
        assertTrue(filter.isDangerousScheme("about:addons"))
        assertTrue(filter.isDangerousScheme("about:debugging"))
        assertTrue(filter.isDangerousScheme("view-source:https://example.com"))
        assertTrue(filter.isDangerousScheme("data:text/html,<h1>bypass</h1>"))
        assertTrue(filter.isDangerousScheme("file:///sdcard/bypass.html"))
        assertFalse(filter.isDangerousScheme("about:blank"))
        assertFalse(filter.isDangerousScheme(ColdTurkeyFilter.BLOCKED_PAGE_URI))
    }

    @Test
    fun blocksWindowTitleKeywordWildcards() {
        val filter = ColdTurkeyFilter.fromRuleLines(loadPackagedRules())
        assertTrue(filter.shouldBlockTitle("Best Free VPN Download 2026"))
        assertTrue(filter.shouldBlockTitle("\u062A\u062D\u0645\u064A\u0644 \u0628\u0631\u0648\u0643\u0633\u064A \u0645\u062C\u0627\u0646\u064A"))
        assertFalse(filter.shouldBlockTitle("Wikipedia - Android operating system"))
    }

    @Test
    fun enforcesSafeSearchParameters() {
        val filter = ColdTurkeyFilter.fromRuleLines(emptyList())
        assertEquals(
            "https://www.google.com/search?q=cats&safe=active",
            filter.enforceSafeSearchUrl("https://www.google.com/search?q=cats")
        )
        assertNull(filter.enforceSafeSearchUrl("https://www.google.com/search?q=cats&safe=active"))
        assertEquals(
            "https://www.bing.com/search?q=cats&adlt=strict",
            filter.enforceSafeSearchUrl("https://www.bing.com/search?q=cats")
        )
        assertNull(filter.enforceSafeSearchUrl("https://www.bing.com/search?q=cats&adlt=strict"))
    }
}
