package com.petal.browser.compose.settings.screens

import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.ui.draw.rotate
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import com.petal.browser.ui.kit.TextField
import com.petal.browser.ui.kit.Button
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.preference.PreferenceManager
import com.petal.browser.R
import com.petal.browser.browser.PetalAdBlockEngine
import com.petal.browser.compose.settings.viewmodel.PrivacySettingsViewModel
import com.petal.browser.passwords.PetalPasswordsScreen
import com.petal.browser.ui.components.ExpressiveHeader
import com.petal.browser.ui.components.M3ExpressiveVariableBackground
import com.petal.browser.ui.components.scrollMotionBlur
import com.petal.browser.ui.containment.*
import com.petal.browser.ui.glass.LocalPetalGlassWallpaper
import com.petal.browser.ui.glass.rememberPetalGlassWallpaper
import java.text.NumberFormat

/**
 * Unified Privacy & Security Screen (Stage 5 Consolidation)
 * Single coherent page in Petal containment style organized into 7 core pillars:
 * 1. Ad & Tracker Blocking (live counter, master switch, filter lists, site exceptions whitelist)
 * 2. Tracking Protection (Standard/Strict segmented control, Total Cookie Protection, Unlinkable Session Partitioning)
 * 3. Fingerprinting Protection (Gecko RFP / FPP primary defense, Canvas/Audio randomization)
 * 4. Connection Security (HTTPS-Only, Private DNS / DoH, WebRTC leak shield, Privacy signals GPC+DNT, Strict referrer trimming)
 * 5. Site Permissions & Content (Popups, GDPR cookie banners, JavaScript)
 * 6. Private Browsing (Biometric lock, Clear on exit)
 * 7. Passwords & Passkeys (Unified Password manager & autofill vault)
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun PrivacySettingsScreen(
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    targetHighlightItemId: String? = null,
    viewModel: PrivacySettingsViewModel = hiltViewModel()
) {
    val adBlockEnabled by viewModel.adBlockEnabled.collectAsStateWithLifecycle()
    val blockThirdPartyCookies by viewModel.blockThirdPartyCookies.collectAsStateWithLifecycle()
    val totalCookieProtection by viewModel.totalCookieProtection.collectAsStateWithLifecycle()
    val cookieBannerAutoReject by viewModel.cookieBannerAutoReject.collectAsStateWithLifecycle()
    val etpStrict by viewModel.etpStrict.collectAsStateWithLifecycle()
    val biometricTabLock by viewModel.biometricTabLock.collectAsStateWithLifecycle()
    val sessionPartitioning by viewModel.sessionPartitioning.collectAsStateWithLifecycle()
    val fingerprintProtection by viewModel.fingerprintProtection.collectAsStateWithLifecycle()
    val webrtcProtection by viewModel.webrtcProtection.collectAsStateWithLifecycle()
    val dntGpc by viewModel.dntGpc.collectAsStateWithLifecycle()
    val trimReferrers by viewModel.trimReferrers.collectAsStateWithLifecycle()
    val httpsOnly by viewModel.httpsOnly.collectAsStateWithLifecycle()
    val javaScriptEnabled by viewModel.javaScriptEnabled.collectAsStateWithLifecycle()
    val blockPopups by viewModel.blockPopups.collectAsStateWithLifecycle()
    val openRedirectsInBackground by viewModel.openRedirectsInBackground.collectAsStateWithLifecycle()
    val privateDnsMode by viewModel.privateDnsMode.collectAsStateWithLifecycle()
    val customDohUrl by viewModel.customDohUrl.collectAsStateWithLifecycle()
    val nextDnsProfileId by viewModel.nextDnsProfileId.collectAsStateWithLifecycle()
    val bounceTracking by viewModel.bounceTracking.collectAsStateWithLifecycle()
    val canvasLetterboxing by viewModel.canvasLetterboxing.collectAsStateWithLifecycle()
    val drmEnabled by viewModel.drmEnabled.collectAsStateWithLifecycle()
    val loginAutofillEnabled by viewModel.loginAutofillEnabled.collectAsStateWithLifecycle()

    PrivacySettingsScreenContent(
        adBlockEnabled = adBlockEnabled,
        blockThirdPartyCookies = blockThirdPartyCookies,
        totalCookieProtection = totalCookieProtection,
        cookieBannerAutoReject = cookieBannerAutoReject,
        etpStrict = etpStrict,
        biometricTabLock = biometricTabLock,
        sessionPartitioning = sessionPartitioning,
        fingerprintProtection = fingerprintProtection,
        webrtcProtection = webrtcProtection,
        dntGpc = dntGpc,
        trimReferrers = trimReferrers,
        httpsOnly = httpsOnly,
        javaScriptEnabled = javaScriptEnabled,
        blockPopups = blockPopups,
        openRedirectsInBackground = openRedirectsInBackground,
        privateDnsMode = privateDnsMode,
        customDohUrl = customDohUrl,
        nextDnsProfileId = nextDnsProfileId,
        bounceTracking = bounceTracking,
        canvasLetterboxing = canvasLetterboxing,
        drmEnabled = drmEnabled,
        loginAutofillEnabled = loginAutofillEnabled,
        onAdBlockEnabledChange = viewModel::setAdBlockEnabled,
        onBlockThirdPartyCookiesChange = viewModel::setBlockThirdPartyCookies,
        onTotalCookieProtectionChange = viewModel::setTotalCookieProtection,
        onCookieBannerAutoRejectChange = viewModel::setCookieBannerAutoReject,
        onEtpStrictChange = viewModel::setEtpStrict,
        onBiometricTabLockChange = viewModel::setBiometricTabLock,
        onSessionPartitioningChange = viewModel::setSessionPartitioning,
        onFingerprintProtectionChange = viewModel::setFingerprintProtection,
        onWebrtcProtectionChange = viewModel::setWebrtcProtection,
        onDntGpcChange = viewModel::setDntGpc,
        onTrimReferrersChange = viewModel::setTrimReferrers,
        onHttpsOnlyChange = viewModel::setHttpsOnly,
        onJavaScriptEnabledChange = viewModel::setJavaScriptEnabled,
        onBlockPopupsChange = viewModel::setBlockPopups,
        onOpenRedirectsInBackgroundChange = viewModel::setOpenRedirectsInBackground,
        onPrivateDnsModeChange = viewModel::setPrivateDnsMode,
        onCustomDohUrlChange = viewModel::setCustomDohUrl,
        onNextDnsProfileIdChange = viewModel::setNextDnsProfileId,
        onBounceTrackingChange = viewModel::setBounceTracking,
        onCanvasLetterboxingChange = viewModel::setCanvasLetterboxing,
        onDrmEnabledChange = viewModel::setDrmEnabled,
        onLoginAutofillEnabledChange = viewModel::setLoginAutofillEnabled,
        onNavigateBack = onNavigateBack,
        targetHighlightItemId = targetHighlightItemId,
        modifier = modifier
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun PrivacySettingsScreenContent(
    adBlockEnabled: Boolean,
    blockThirdPartyCookies: Boolean,
    totalCookieProtection: Boolean = true,
    cookieBannerAutoReject: Boolean = true,
    etpStrict: Boolean = true,
    biometricTabLock: Boolean = false,
    sessionPartitioning: Boolean = true,
    fingerprintProtection: Boolean,
    webrtcProtection: Boolean,
    dntGpc: Boolean,
    trimReferrers: Boolean,
    httpsOnly: Boolean,
    javaScriptEnabled: Boolean,
    blockPopups: Boolean,
    openRedirectsInBackground: Boolean,
    privateDnsMode: String,
    customDohUrl: String,
    nextDnsProfileId: String = "",
    bounceTracking: Boolean = false,
    canvasLetterboxing: Boolean = false,
    drmEnabled: Boolean = true,
    loginAutofillEnabled: Boolean = true,
    onAdBlockEnabledChange: (Boolean) -> Unit,
    onBlockThirdPartyCookiesChange: (Boolean) -> Unit,
    onTotalCookieProtectionChange: (Boolean) -> Unit = {},
    onCookieBannerAutoRejectChange: (Boolean) -> Unit = {},
    onEtpStrictChange: (Boolean) -> Unit = {},
    onBiometricTabLockChange: (Boolean) -> Unit = {},
    onSessionPartitioningChange: (Boolean) -> Unit = {},
    onFingerprintProtectionChange: (Boolean) -> Unit,
    onWebrtcProtectionChange: (Boolean) -> Unit,
    onDntGpcChange: (Boolean) -> Unit,
    onTrimReferrersChange: (Boolean) -> Unit,
    onHttpsOnlyChange: (Boolean) -> Unit,
    onJavaScriptEnabledChange: (Boolean) -> Unit,
    onBlockPopupsChange: (Boolean) -> Unit,
    onOpenRedirectsInBackgroundChange: (Boolean) -> Unit,
    onPrivateDnsModeChange: (String) -> Unit,
    onCustomDohUrlChange: (String) -> Unit,
    onNextDnsProfileIdChange: (String) -> Unit = {},
    onBounceTrackingChange: (Boolean) -> Unit = {},
    onCanvasLetterboxingChange: (Boolean) -> Unit = {},
    onDrmEnabledChange: (Boolean) -> Unit = {},
    onLoginAutofillEnabledChange: (Boolean) -> Unit = {},
    onNavigateBack: () -> Unit,
    targetHighlightItemId: String? = null,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val sp = remember(context) { PreferenceManager.getDefaultSharedPreferences(context) }
    val ambientWallpaper = LocalPetalGlassWallpaper.current
    val wallpaper = ambientWallpaper ?: rememberPetalGlassWallpaper()
    val isGlass = isLiquidGlassEnabled("sp_liquid_glass_containments")

    var showPasswordsScreen by remember { mutableStateOf(false) }
    var showAdBlockSettings by remember { mutableStateOf(false) }
    var showWhitelistDialog by remember { mutableStateOf(false) }
    var showDeleteScreenDialog by remember { mutableStateOf(false) }
    var whitelistDomainInput by remember { mutableStateOf("") }
    var whitelistedDomainsState by remember { mutableStateOf(PetalAdBlockEngine.getWhitelistedDomains()) }

    var clearOnExit by remember {
        mutableStateOf(sp.getBoolean("sp_clear_quit", false) || sp.getBoolean("sp_clear_on_exit", false))
    }

    val totalBlockedCount = remember(adBlockEnabled) {
        PetalAdBlockEngine.getTotalBlockedCount()
    }

    if (showAdBlockSettings) {
        PetalAdBlockSettingsScreen(
            onNavigateBack = {
                showAdBlockSettings = false
                whitelistedDomainsState = PetalAdBlockEngine.getWhitelistedDomains()
            },
            modifier = modifier
        )
        return
    }

    if (showWhitelistDialog) {
        PetalAlertDialog(
            onDismissRequest = { showWhitelistDialog = false },
            title = stringResource(R.string.ui_adblock_domain_whitelist),
            confirmText = stringResource(R.string.ui_done),
            onConfirm = { showWhitelistDialog = false },
            dismissText = null,
            icon = Icons.Rounded.FilterList,
            content = {
                Text(
                    stringResource(R.string.ui_domains_added_here_will_bypass),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    TextField(
                        value = whitelistDomainInput,
                        onValueChange = { whitelistDomainInput = it },
                        placeholder = { Text("example.com") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(topStart = 50.dp, bottomStart = 50.dp, topEnd = 6.dp, bottomEnd = 6.dp),
                        colors = TextFieldDefaults.colors(
                            focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                            focusedIndicatorColor = Color.Transparent,
                            unfocusedIndicatorColor = Color.Transparent
                        )
                    )
                    Button(
                        onClick = {
                            if (whitelistDomainInput.isNotBlank()) {
                                PetalAdBlockEngine.addDomainToWhitelist(context, whitelistDomainInput.trim())
                                whitelistedDomainsState = PetalAdBlockEngine.getWhitelistedDomains()
                                whitelistDomainInput = ""
                            }
                        },
                        shape = RoundedCornerShape(topStart = 6.dp, bottomStart = 6.dp, topEnd = 50.dp, bottomEnd = 50.dp)
                    ) {
                        Text(stringResource(R.string.ui_add))
                    }
                }

                if (whitelistedDomainsState.isEmpty()) {
                    Text(
                        stringResource(R.string.ui_no_whitelisted_domains),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                } else {
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        whitelistedDomainsState.forEach { domain ->
                            InputChip(
                                selected = true,
                                onClick = {
                                    PetalAdBlockEngine.removeDomainFromWhitelist(context, domain)
                                    whitelistedDomainsState = PetalAdBlockEngine.getWhitelistedDomains()
                                },
                                label = { Text(domain) },
                                trailingIcon = {
                                    Icon(
                                        Icons.Rounded.Close,
                                        contentDescription = stringResource(R.string.ui_remove),
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                            )
                        }
                    }
                }
            }
        )
    }

    CompositionLocalProvider(LocalPetalGlassWallpaper provides wallpaper) {
        val passwordsActivity = context as? ComponentActivity
        // The Password Manager is a real sub-page: this page stays composed (and blurred / dimmed by the
        // sub-page's own back gesture) behind it, instead of a bare overlay with nothing behind it.
        com.petal.browser.predictive.PetalSubPageHost(
            visible = showPasswordsScreen && passwordsActivity != null,
            onBack = { showPasswordsScreen = false },
            modifier = modifier,
            subPage = {
                if (passwordsActivity != null) {
                    PetalPasswordsScreen(
                        activity = passwordsActivity,
                        onNavigateBack = { showPasswordsScreen = false },
                        embedded = true
                    )
                }
            },
            parent = {
        Box(modifier = Modifier.fillMaxSize()) {
            M3ExpressiveVariableBackground(
                pageSeed = "privacy_settings",
                modifier = Modifier.matchParentSize()
            )

            com.petal.browser.ui.components.PetalGlassHeaderLayout(
                modifier = Modifier.fillMaxSize(),
                header = { headerModifier, headerBackdrop ->
                    ExpressiveHeader(
                        modifier = headerModifier,
                        backdrop = headerBackdrop,
                        title = "Privacy & Security",
                        subtitle = "AdBlock, Tracking Protection & Connection Security",
                        onBack = onNavigateBack
                    )
                }
            ) { topInset ->

                val scrollState = rememberScrollState()
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .fillMaxSize()
                        .scrollMotionBlur(scrollState)
                        .verticalScroll(scrollState, flingBehavior = com.petal.browser.ui.theme.layout.petalFlingBehavior())
                        .padding(start = 16.dp, end = 16.dp, top = topInset + 12.dp, bottom = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    // Ad & Tracker Blocking controls are locked ON in SafeBrowser

                    // ── 2. Tracking Protection (Standard / Strict + TCP + Session Partitioning) ──
                    PetalSettingsSection(
                        title = "Tracking Protection",
                        icon = Icons.Rounded.Security,
                        cardId = "privacy_etp",
                        targetHighlightId = targetHighlightItemId
                    ) {
                        val trackingModes = listOf(
                            Pair(false, Pair("Standard", "Balanced protection: blocks trackers in private windows, isolates third-party cookies")),
                            Pair(true, Pair("Strict (Recommended)", "Maximum protection: blocks known trackers in all windows, fingerprinters, and cryptominers"))
                        )

                        PetalGroup(rowCount = trackingModes.size) { index, position ->
                            val (isStrict, info) = trackingModes[index]
                            val (title, subtitle) = info
                            val isSelected = etpStrict == isStrict
                            PetalGroupListRow(
                                position = position,
                                selected = isSelected,
                                onClick = { onEtpStrictChange(isStrict) },
                                leading = {
                                    PetalGroupIconBadge(
                                        icon = if (isStrict) Icons.Rounded.Security else Icons.Rounded.Shield,
                                        variant = if (isSelected) PetalBadgeVariant.PRIMARY else PetalBadgeVariant.SURFACE_TONAL
                                    )
                                },
                                content = {
                                    Text(
                                        text = title,
                                        style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.SemiBold),
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                    Text(
                                        text = subtitle,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                },
                                trailing = {
                                    if (isSelected) {
                                        Icon(
                                            Icons.Rounded.CheckCircle,
                                            contentDescription = null,
                                            tint = MaterialTheme.colorScheme.primary,
                                            modifier = Modifier.size(22.dp)
                                        )
                                    }
                                }
                            )
                        }

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[0],
                            position = PetalGroupPosition.MIDDLE,
                            title = "Total Cookie Protection",
                            subtitle = "Dynamic first-party cookie jar isolation and state partitioning",
                            icon = Icons.Rounded.Cookie,
                            checked = totalCookieProtection,
                            onCheckedChange = { newValue ->
                                onTotalCookieProtectionChange(newValue)
                                onBlockThirdPartyCookiesChange(newValue)
                            }
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[1],
                            position = PetalGroupPosition.MIDDLE,
                            title = "Unlinkable Session Partitioning",
                            subtitle = "Isolates client network state per tab session to defeat bounce tracking",
                            icon = Icons.Rounded.Splitscreen,
                            checked = sessionPartitioning,
                            onCheckedChange = onSessionPartitioningChange
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[2],
                            position = PetalGroupPosition.BOTTOM,
                            title = "Bounce Tracking Protection",
                            subtitle = "Purges redirect tracker state when traversing bounce redirect intermediaries",
                            icon = Icons.Rounded.AltRoute,
                            checked = bounceTracking,
                            onCheckedChange = onBounceTrackingChange
                        )
                    }

                    // ── 3. Fingerprinting Protection (Gecko RFP / FPP Primary Defense) ──
                    PetalSettingsSection(
                        title = "Fingerprinting Protection",
                        icon = Icons.Rounded.Fingerprint,
                        cardId = "privacy_fingerprinting",
                        targetHighlightId = targetHighlightItemId
                    ) {
                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[0],
                            position = PetalGroupPosition.TOP,
                            title = "Resist Fingerprinting (Gecko RFP)",
                            subtitle = "Uniform canvas, audio context, hardware metrics, and reduced timer precision",
                            icon = Icons.Rounded.Fingerprint,
                            checked = fingerprintProtection,
                            onCheckedChange = onFingerprintProtectionChange
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[1],
                            position = PetalGroupPosition.BOTTOM,
                            title = "Canvas Letterboxing",
                            subtitle = "Appends margins to canvas viewport to prevent display dimension fingerprinting",
                            icon = Icons.Rounded.AspectRatio,
                            checked = canvasLetterboxing,
                            onCheckedChange = onCanvasLetterboxingChange
                        )
                    }

                    // ── 4. Connection & DNS (HTTPS-Only, DoH, WebRTC, GPC/DNT, Referrer) ──
                    PetalSettingsSection(
                        title = "Connection & DNS",
                        icon = Icons.Rounded.Lock,
                        cardId = "privacy_connection",
                        targetHighlightId = targetHighlightItemId
                    ) {
                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[2],
                            position = PetalGroupPosition.TOP,
                            title = "HTTPS-Only Mode",
                            subtitle = "Automatically upgrade connections to HTTPS and warn on insecure HTTP",
                            icon = Icons.Rounded.Https,
                            checked = httpsOnly,
                            onCheckedChange = onHttpsOnlyChange
                        )

                        // DNS-over-HTTPS is locked to AdGuard Family DNS (TRR Mode 3)

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[0],
                            position = PetalGroupPosition.MIDDLE,
                            title = "WebRTC IP Leak Protection",
                            subtitle = "Prevents leaking local private IP address via WebRTC peer connections",
                            icon = Icons.Rounded.WifiProtectedSetup,
                            checked = webrtcProtection,
                            onCheckedChange = onWebrtcProtectionChange
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[1],
                            position = PetalGroupPosition.MIDDLE,
                            title = "Privacy Signals (GPC + DNT)",
                            subtitle = "Broadcasts Global Privacy Control and Do Not Track signals with every HTTP request",
                            icon = Icons.Rounded.Security,
                            checked = dntGpc,
                            onCheckedChange = onDntGpcChange
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[2],
                            position = PetalGroupPosition.BOTTOM,
                            title = "Strict Referrer Trimming",
                            subtitle = "Strips cross-origin URL paths and query parameters from HTTP Referer headers (default on)",
                            icon = Icons.Rounded.LinkOff,
                            checked = trimReferrers,
                            onCheckedChange = onTrimReferrersChange
                        )
                    }

                    // ── 5. Site Permissions & Content (Popups, Cookie Banners, JavaScript) ──
                    PetalSettingsSection(
                        title = "Site Permissions & Content",
                        icon = Icons.Rounded.Code,
                        cardId = "privacy_content",
                        targetHighlightId = targetHighlightItemId
                    ) {
                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[0],
                            position = PetalGroupPosition.TOP,
                            title = "Block Pop-up Windows",
                            subtitle = "Prevents unwanted new windows and intrusive redirects",
                            icon = Icons.Rounded.OpenInNew,
                            checked = blockPopups,
                            onCheckedChange = onBlockPopupsChange
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[1],
                            position = PetalGroupPosition.MIDDLE,
                            title = "Auto-Reject Cookie Banners (GDPR)",
                            subtitle = "Automatically declines cookie consent popups and modals",
                            icon = Icons.Rounded.VerifiedUser,
                            checked = cookieBannerAutoReject,
                            onCheckedChange = onCookieBannerAutoRejectChange
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[2],
                            position = PetalGroupPosition.MIDDLE,
                            title = "JavaScript",
                            subtitle = "Enable JavaScript execution for web pages",
                            icon = Icons.Rounded.Code,
                            checked = javaScriptEnabled,
                            onCheckedChange = onJavaScriptEnabledChange
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[0],
                            position = PetalGroupPosition.BOTTOM,
                            title = "DRM Content Playback",
                            subtitle = "Allow playing DRM-protected digital media (Widevine)",
                            icon = Icons.Rounded.PlayCircle,
                            checked = drmEnabled,
                            onCheckedChange = onDrmEnabledChange
                        )
                    }

                    // ── 6. Browsing Data (Clear Browsing Data, Clear on Exit) ──
                    PetalSettingsSection(
                        title = "Browsing Data",
                        icon = Icons.Rounded.DeleteSweep,
                        cardId = "privacy_browsing_data",
                        targetHighlightId = targetHighlightItemId
                    ) {
                        com.petal.browser.ui.containment.PetalGroupRow(
                            position = PetalGroupPosition.TOP,
                            title = "Clear Browsing Data",
                            subtitle = "Permanently remove history, cache, cookies, and local database storage",
                            icon = Icons.Rounded.DeleteOutline,
                            onClick = { showDeleteScreenDialog = true }
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[2],
                            position = PetalGroupPosition.BOTTOM,
                            title = "Clear Data on Exit",
                            subtitle = "Automatically purge cache, cookies, and browsing sessions when closing Petal",
                            icon = Icons.Rounded.DeleteSweep,
                            checked = clearOnExit,
                            onCheckedChange = { newValue ->
                                clearOnExit = newValue
                                sp.edit()
                                    .putBoolean("sp_clear_quit", newValue)
                                    .putBoolean("sp_clear_on_exit", newValue)
                                    .apply()
                            }
                        )
                    }

                    // ── 7. Passwords & Passkeys (Unified Manager & Vault) ──
                    PetalSettingsSection(
                        title = "Passwords & Passkeys",
                        icon = Icons.Rounded.VpnKey,
                        cardId = "privacy_passwords",
                        targetHighlightId = targetHighlightItemId
                    ) {
                        PetalGroupNavigationRow(
                            variant = privacyRowVariants[0],
                            title = "Password Manager & Autofill Vault",
                            subtitle = "Encrypted local credentials, passkeys, and breach alert monitoring",
                            position = PetalGroupPosition.TOP,
                            onClick = { showPasswordsScreen = true },
                            leadingIcon = { Icon(Icons.Rounded.VpnKey, contentDescription = null) }
                        )

                        PetalSettingsToggleRow(
                            variant = privacyRowVariants[1],
                            position = PetalGroupPosition.BOTTOM,
                            title = "Autofill Logins & Passwords",
                            subtitle = "Automatically suggest and fill saved credentials on web forms",
                            icon = Icons.Rounded.Password,
                            checked = loginAutofillEnabled,
                            onCheckedChange = onLoginAutofillEnabledChange
                        )
                    }
                }
            }
        }

        if (showDeleteScreenDialog) {
            Box(modifier = Modifier.fillMaxSize()) {
                com.petal.browser.compose.settings.PetalDeleteScreen(
                    onBackPress = { showDeleteScreenDialog = false }
                )
            }
        }
            }
        )
    }
}

/** Same badge colour cycle the Settings hub and Account rows use. */
private val privacyRowVariants = listOf(PetalBadgeVariant.PRIMARY, PetalBadgeVariant.SECONDARY, PetalBadgeVariant.TERTIARY)

private data class DnsChoice(val mode: String, val label: String, val desc: String)

private sealed interface DnsEntry {
    data class Single(val mode: String, val title: String, val desc: String, val custom: Boolean) : DnsEntry
    data class Group(val provider: String, val choices: List<DnsChoice>) : DnsEntry
}
