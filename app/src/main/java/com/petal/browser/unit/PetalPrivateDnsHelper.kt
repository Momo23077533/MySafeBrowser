package com.petal.browser.unit

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager

/**
 * Modern DNS-over-HTTPS (DoH) configuration helper for Petal Browser.
 * Modernized from legacy PrivateDnsUnit.
 */
object PetalPrivateDnsHelper {
    const val DNS_OFF = "OFF"
    const val DNS_CLOUDFLARE = "CLOUDFLARE"
    const val DNS_GOOGLE = "GOOGLE"
    const val DNS_CLEANBROWSING = "CLEANBROWSING"
    const val DNS_OPENDNS = "OPENDNS"
    const val DNS_NEXTDNS = "NEXTDNS"
    const val DNS_QUAD9 = "QUAD9"
    const val DNS_CUSTOM = "CUSTOM"

    const val PREF_MODE = "sp_private_dns_mode"
    const val PREF_NEXTDNS_PROFILE = "sp_nextdns_profile_id"
    const val FORCED_DOH_URI = "https://family.adguard-dns.com/dns-query"

    @JvmStatic
    fun getDnsProviderName(context: Context?): String = "AdGuard Family DNS (Locked)"

    @JvmStatic
    fun getDnsHostname(context: Context?): String? {
        if (context == null) return null
        val sp = PreferenceManager.getDefaultSharedPreferences(context)
        val mode = sp.getString(PREF_MODE, DNS_OFF) ?: return null
        return PetalDnsCatalog.find(mode)?.hostname
    }

    @JvmStatic
    fun getDnsEndpointUrl(sp: SharedPreferences?): String = FORCED_DOH_URI

    @JvmStatic
    fun getDnsEndpointUrl(context: Context?): String? {
        if (context == null) return null
        return getDnsEndpointUrl(PreferenceManager.getDefaultSharedPreferences(context))
    }

    @JvmStatic
    fun isPrivateDnsActive(context: Context?): Boolean = true
}
