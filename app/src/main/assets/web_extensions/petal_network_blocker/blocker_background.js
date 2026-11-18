// Petal Network Blocker - Background Service Script
// Layer 1: Synchronous in-memory Cold Turkey 3-tier family filter + SafeSearch enforcement
// Layer 2: Brave adblock-rust subresource & cosmetic filter engine

(function () {
    "use strict";

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Cold Turkey 3-Tier Deterministic Engine (Synchronous, In-Memory)
    // ─────────────────────────────────────────────────────────────────────────
    const COLD_TURKEY_RULE_FILES = ["rules/Tofan websites.txt"];
    const COLD_TURKEY_ALLOW_FILES = ["rules/allowed.txt"];

    function isHexChar(ch) {
        return (ch >= "0" && ch <= "9") || (ch >= "a" && ch <= "f") || (ch >= "A" && ch <= "F");
    }

    function safePercentDecode(str) {
        try {
            return decodeURIComponent(str);
        } catch (_) {
            // Segment-safe fallback so one malformed % sequence never prevents decoding valid UTF-8 (%D8%...)
            let out = "";
            let i = 0;
            while (i < str.length) {
                if (str[i] === "%") {
                    let j = i;
                    while (j + 2 < str.length && str[j] === "%" && isHexChar(str[j + 1]) && isHexChar(str[j + 2])) {
                        j += 3;
                    }
                    if (j > i) {
                        const chunk = str.slice(i, j);
                        try {
                            out += decodeURIComponent(chunk);
                        } catch (_e) {
                            out += chunk;
                        }
                        i = j;
                        continue;
                    }
                }
                out += str[i];
                i++;
            }
            return out;
        }
    }

    function normalizeAndDecode(input) {
        if (!input || typeof input !== "string") return "";
        let current = input.replace(/\+/g, " ");
        for (let pass = 0; pass < 2; pass++) {
            const decoded = safePercentDecode(current);
            if (decoded === current) break;
            current = decoded;
        }
        return current.toLowerCase();
    }

    function compileWildcard(lowerRule) {
        try {
            let pattern = "";
            for (let i = 0; i < lowerRule.length; i++) {
                const ch = lowerRule[i];
                if (ch === "*") {
                    pattern += ".*";
                } else if (".+?^$()[]{}|\\".indexOf(ch) !== -1) {
                    pattern += "\\" + ch;
                } else {
                    pattern += ch;
                }
            }
            return { raw: lowerRule, regex: new RegExp(pattern, "i") };
        } catch (_) {
            return null;
        }
    }

    function isHostOnlyWildcard(lowerRule) {
        if (lowerRule.startsWith("*")) return false;
        if (lowerRule.indexOf("/") !== -1 || lowerRule.indexOf("?") !== -1 || lowerRule.indexOf(":") !== -1) {
            return false;
        }
        return true;
    }

    function extractHostFromUrl(lowerUrl) {
        try {
            const h = new URL(lowerUrl).hostname;
            if (h) return h.toLowerCase().replace(/^www\./, "");
        } catch (_) {}
        const schemeIdx = lowerUrl.indexOf("://");
        if (schemeIdx < 0) return "";
        const start = schemeIdx + 3;
        let end = lowerUrl.length;
        for (const sep of ["/", "?", "#", ":"]) {
            const idx = lowerUrl.indexOf(sep, start);
            if (idx >= start && idx < end) end = idx;
        }
        let auth = lowerUrl.slice(start, end);
        const atIdx = auth.lastIndexOf("@");
        if (atIdx >= 0) auth = auth.slice(atIdx + 1);
        return auth.replace(/^www\./, "");
    }

    function extractPathFromUrl(lowerUrl) {
        const schemeIdx = lowerUrl.indexOf("://");
        const start = schemeIdx >= 0 ? schemeIdx + 3 : 0;
        const slashIdx = lowerUrl.indexOf("/", start);
        if (slashIdx < 0) return "/";
        const qIdx = lowerUrl.indexOf("?", slashIdx);
        const hIdx = lowerUrl.indexOf("#", slashIdx);
        let end = lowerUrl.length;
        if (qIdx >= 0 && qIdx < end) end = qIdx;
        if (hIdx >= 0 && hIdx < end) end = hIdx;
        return lowerUrl.slice(slashIdx, end);
    }

    function extractPathAndQueryFromUrl(lowerUrl) {
        const schemeIdx = lowerUrl.indexOf("://");
        const start = schemeIdx >= 0 ? schemeIdx + 3 : 0;
        const slashIdx = lowerUrl.indexOf("/", start);
        if (slashIdx < 0) return "/";
        const hIdx = lowerUrl.indexOf("#", slashIdx);
        return hIdx >= 0 ? lowerUrl.slice(slashIdx, hIdx) : lowerUrl.slice(slashIdx);
    }

    function matchesDomainSet(host, domainSet) {
        if (!host || domainSet.size === 0) return false;
        let candidate = host;
        while (candidate.length > 0) {
            if (domainSet.has(candidate)) return true;
            const dot = candidate.indexOf(".");
            if (dot < 0 || dot === candidate.length - 1) break;
            candidate = candidate.slice(dot + 1);
        }
        return false;
    }

    function matchesPathRules(host, rawLower, decodedLower, rules) {
        if (!host || rules.length === 0) return false;
        const rawPath = extractPathAndQueryFromUrl(rawLower);
        const decPath = extractPathAndQueryFromUrl(decodedLower);
        for (let i = 0; i < rules.length; i++) {
            const r = rules[i];
            if (host === r.host || host.endsWith("." + r.host)) {
                if (rawPath.startsWith(r.pathPrefix) || decPath.startsWith(r.pathPrefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    function matchesWildcards(list, rawLower, decodedLower) {
        for (let i = 0; i < list.length; i++) {
            const rx = list[i].regex;
            if (rx.test(rawLower)) return true;
            if (decodedLower !== rawLower && rx.test(decodedLower)) return true;
        }
        return false;
    }

    function createColdTurkeyMatcher(blockRuleLines, allowRuleLines) {
        const tier1KeywordWildcards = [];
        const tier2AllowDomains = new Set();
        const tier2AllowPathRules = [];
        const tier2AllowWildcards = [];
        const tier3BlockDomains = new Set();
        const tier3BlockPathRules = [];
        const tier3BlockSchemes = new Set();
        const tier3BlockWildcards = [];
        let totalRuleLines = 0;

        function parseAllowRule(raw) {
            if (typeof raw !== "string") return;
            const clean = raw.trim();
            if (!clean || clean.startsWith("#")) return;
            const lower = clean.toLowerCase();
            if (lower.startsWith("*.")) {
                const base = lower.slice(2);
                if (base.indexOf("*") === -1 && base.indexOf("/") === -1) {
                    tier2AllowDomains.add(base.replace(/^www\./, ""));
                    return;
                }
            }
            if (lower.indexOf("*") !== -1) {
                const c = compileWildcard(lower);
                if (c) tier2AllowWildcards.push(c);
            } else if (lower.indexOf("/") !== -1) {
                const idx = lower.indexOf("/");
                const host = lower.slice(0, idx).replace(/^www\./, "");
                const path = lower.slice(idx);
                if (host) tier2AllowPathRules.push({ host: host, pathPrefix: path });
            } else {
                tier2AllowDomains.add(lower.replace(/^www\./, ""));
            }
        }

        if (Array.isArray(allowRuleLines)) {
            for (let i = 0; i < allowRuleLines.length; i++) {
                parseAllowRule(allowRuleLines[i]);
            }
        }

        if (Array.isArray(blockRuleLines)) {
            for (let i = 0; i < blockRuleLines.length; i++) {
                const rawLine = blockRuleLines[i];
                if (typeof rawLine !== "string") continue;
                const trimmed = rawLine.trim();
                if (!trimmed || trimmed.startsWith("#")) continue;
                totalRuleLines++;

                if (trimmed.startsWith("@@")) {
                    parseAllowRule(trimmed.slice(2));
                    continue;
                }

                const lower = trimmed.toLowerCase();

                // Pure subdomain wildcard *.example.com -> Tier 3 domain rule
                if (lower.startsWith("*.") && lower.slice(2).indexOf("*") === -1 && lower.indexOf("/") === -1 && lower.indexOf("?") === -1) {
                    const domain = lower.slice(2).replace(/^www\./, "");
                    if (domain) {
                        tier3BlockDomains.add(domain);
                        continue;
                    }
                }

                // Scheme rule without wildcard
                if (lower.indexOf("*") === -1 && (lower.endsWith(":") || lower.indexOf("://") !== -1)) {
                    tier3BlockSchemes.add(lower);
                    continue;
                }

                // Wildcard rules
                if (lower.indexOf("*") !== -1) {
                    const compiled = compileWildcard(lower);
                    if (!compiled) continue;
                    if (isHostOnlyWildcard(lower)) {
                        tier3BlockWildcards.push(compiled);
                    } else {
                        tier1KeywordWildcards.push(compiled);
                    }
                    continue;
                }

                // Domain + path rule (e.g., youtube.com/shorts)
                if (lower.indexOf("/") !== -1) {
                    const idx = lower.indexOf("/");
                    const host = lower.slice(0, idx).replace(/^www\./, "");
                    const path = lower.slice(idx);
                    if (host) {
                        tier3BlockPathRules.push({ host: host, pathPrefix: path });
                    }
                    continue;
                }

                // Plain domain rule
                if (lower.indexOf(".") !== -1) {
                    tier3BlockDomains.add(lower.replace(/^www\./, ""));
                } else {
                    const fallback = compileWildcard("*" + lower + "*");
                    if (fallback) tier1KeywordWildcards.push(fallback);
                }
            }
        }

        function isBlockedPage(lowerUrl) {
            return lowerUrl.startsWith("resource://android/assets/web_extensions/petal_network_blocker/blocked.html") ||
                (lowerUrl.startsWith("moz-extension://") && lowerUrl.indexOf("/blocked.html") !== -1);
        }

        function shouldBlockUrl(url) {
            if (!url || typeof url !== "string") return false;
            const trimmed = url.trim();
            if (!trimmed) return false;
            const rawLower = trimmed.toLowerCase();
            if (rawLower === "about:blank" || rawLower === "about:home" || isBlockedPage(rawLower)) {
                return false;
            }

            const decodedLower = normalizeAndDecode(trimmed);
            const host = extractHostFromUrl(rawLower);

            // Tier 1: Hard Keyword / Search Wildcards (NEVER overridden by allowlist)
            if (matchesWildcards(tier1KeywordWildcards, rawLower, decodedLower)) {
                return true;
            }

            // Tier 2: Allowlist / Exceptions
            if ((host && matchesDomainSet(host, tier2AllowDomains)) ||
                (host && matchesPathRules(host, rawLower, decodedLower, tier2AllowPathRules)) ||
                matchesWildcards(tier2AllowWildcards, rawLower, decodedLower)) {
                return false;
            }

            // Tier 3: Blocked Schemes, Domains, Path Rules & Host Wildcards
            for (const scheme of tier3BlockSchemes) {
                if (rawLower.startsWith(scheme) || decodedLower.startsWith(scheme)) {
                    return true;
                }
            }
            if (host && matchesDomainSet(host, tier3BlockDomains)) {
                return true;
            }
            if (host && matchesPathRules(host, rawLower, decodedLower, tier3BlockPathRules)) {
                return true;
            }
            if (matchesWildcards(tier3BlockWildcards, rawLower, decodedLower)) {
                return true;
            }

            return false;
        }

        function enforceSafeSearchUrl(url) {
            if (!url || typeof url !== "string") return null;
            const lower = url.toLowerCase();
            if (!lower.startsWith("http://") && !lower.startsWith("https://")) return null;

            const host = extractHostFromUrl(lower);
            const path = extractPathFromUrl(lower);

            const isGoogleSearch = (host === "google.com" || host.endsWith(".google.com") || host.indexOf(".google.") !== -1 || host.startsWith("google.")) &&
                (path === "/search" || path.startsWith("/search/"));
            if (isGoogleSearch) {
                if (!/([?&])safe=active(&|$)/i.test(lower)) {
                    const sep = url.indexOf("?") !== -1 ? "&" : "?";
                    return url + sep + "safe=active";
                }
                return null;
            }

            const isBingSearch = (host === "bing.com" || host.endsWith(".bing.com")) &&
                (path === "/search" || path.startsWith("/search/"));
            if (isBingSearch) {
                if (!/([?&])adlt=strict(&|$)/i.test(lower)) {
                    const sep = url.indexOf("?") !== -1 ? "&" : "?";
                    return url + sep + "adlt=strict";
                }
                return null;
            }

            return null;
        }

        return {
            shouldBlockUrl: shouldBlockUrl,
            enforceSafeSearchUrl: enforceSafeSearchUrl,
            normalizeAndDecode: normalizeAndDecode,
            totalRuleLines: totalRuleLines,
            stats: {
                tier1Count: tier1KeywordWildcards.length,
                tier2DomainCount: tier2AllowDomains.size,
                tier2WildcardCount: tier2AllowWildcards.length,
                tier3DomainCount: tier3BlockDomains.size,
                tier3WildcardCount: tier3BlockWildcards.length,
                tier3PathCount: tier3BlockPathRules.length
            }
        };
    }

    function loadAssetTextSync(apiObj, relativePath) {
        if (!apiObj || !apiObj.runtime || typeof apiObj.runtime.getURL !== "function" || typeof XMLHttpRequest === "undefined") {
            return null;
        }
        try {
            const xhr = new XMLHttpRequest();
            xhr.open("GET", apiObj.runtime.getURL(relativePath), false);
            xhr.send(null);
            if ((xhr.status === 200 || xhr.status === 0) && typeof xhr.responseText === "string" && xhr.responseText.length > 0) {
                return xhr.responseText;
            }
        } catch (_) {}
        return null;
    }

    function initColdTurkeyEngineSync(apiObj) {
        const blockLines = [];
        const allowLines = [];

        for (let i = 0; i < COLD_TURKEY_RULE_FILES.length; i++) {
            const text = loadAssetTextSync(apiObj, COLD_TURKEY_RULE_FILES[i]);
            if (text) {
                const lines = text.split(/\r?\n/);
                for (let j = 0; j < lines.length; j++) blockLines.push(lines[j]);
            }
        }
        for (let i = 0; i < COLD_TURKEY_ALLOW_FILES.length; i++) {
            const text = loadAssetTextSync(apiObj, COLD_TURKEY_ALLOW_FILES[i]);
            if (text) {
                const lines = text.split(/\r?\n/);
                for (let j = 0; j < lines.length; j++) allowLines.push(lines[j]);
            }
        }

        return createColdTurkeyMatcher(blockLines, allowLines);
    }

    // Export for Node.js verification tests without needing browser globals
    if (typeof module !== "undefined" && module.exports) {
        module.exports = {
            createColdTurkeyMatcher: createColdTurkeyMatcher,
            normalizeAndDecode: normalizeAndDecode
        };
    }

    const api = (typeof browser !== "undefined") ? browser : (typeof chrome !== "undefined" ? chrome : null);
    if (!api) {
        return;
    }

    // Pre-compile Cold Turkey rules synchronously in memory at extension startup
    const coldTurkeyEngine = initColdTurkeyEngineSync(api);
    const blockedPageBaseUrl = (api.runtime && typeof api.runtime.getURL === "function")
        ? api.runtime.getURL("blocked.html")
        : "resource://android/assets/web_extensions/petal_network_blocker/blocked.html";

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Existing Petal Adblock-Rust Subresource & Cosmetic Engine
    // ─────────────────────────────────────────────────────────────────────────
    const NATIVE_APP = "petalApp";
    let isBlockerEnabled = true; // Permanently enforced
    let blockerMode = "standard";
    let whitelistedHosts = new Set();
    let adblockEngine = null;
    let engineVersion = 0;
    let isEngineLoading = false;

    const REDIRECT_RESOURCES = {
        "noopjs": "data:application/javascript;base64,KGZ1bmN0aW9uKCl7fSkoKTs=",
        "noop.js": "data:application/javascript;base64,KGZ1bmN0aW9uKCl7fSkoKTs=",
        "empty": "data:text/plain;charset=utf-8,",
        "nooptext": "data:text/plain;charset=utf-8,",
        "noopcss": "data:text/css;charset=utf-8,",
        "1x1.transparent.gif": "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
        "1x1-transparent.gif": "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
        "2x2.transparent.png": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAUSURBVBhXY/jPwPD/PwMDAwMDAwMBFgH+v/R/yQAAAABJRU5ErkJggg==",
        "google-analytics_analytics.js": "data:application/javascript;base64,d2luZG93LmdhID0gd2luZG93LmdhIHx8IGZ1bmN0aW9uKCl7fTt3aW5kb3cuZ3RhZyA9IHdpbmRvdy5ndGFnIHx8IGZ1bmN0aW9uKCl7fTs=",
        "googletagservices_gpt.js": "data:application/javascript;base64,d2luZG93Lmdvb2dsZXRhZyA9IHdpbmRvdy5nb29nbGV0YWcgfHwge2NtZDpbXX07",
        "facebook_fbevents.js": "data:application/javascript;base64,d2luZG93LmZicSA9IHdpbmRvdy5mYnEgfHwgZnVuY3Rpb24oKXt9Ow=="
    };

    function normalizeHost(host) {
        if (!host) return "";
        return host.toLowerCase().replace(/^\.+|\.+$/g, "").replace(/^www\./, "");
    }

    function extractDomain(url) {
        if (!url) return "";
        try {
            const h = new URL(url).hostname;
            return normalizeHost(h);
        } catch (_) {
            return "";
        }
    }

    function getBaseDomain(hostname) {
        if (!hostname) return "";
        const parts = hostname.toLowerCase().split(".");
        if (parts.length <= 2) return hostname;
        const secondLast = parts[parts.length - 2];
        if (["co", "com", "org", "net", "edu", "gov"].includes(secondLast) && parts.length > 2) {
            return parts.slice(-3).join(".");
        }
        return parts.slice(-2).join(".");
    }

    function isFirstParty(targetUrl, sourceUrl) {
        if (!sourceUrl || !targetUrl) return true;
        const targetHost = extractDomain(targetUrl);
        const sourceHost = extractDomain(sourceUrl);
        if (!targetHost || !sourceHost) return true;
        return getBaseDomain(targetHost) === getBaseDomain(sourceHost);
    }

    const pendingCspHeaders = new Map();

    async function initAdblockEngine() {
        if (isEngineLoading) return;
        isEngineLoading = true;
        try {
            if (typeof WebAssembly !== "undefined" && api.runtime && typeof api.runtime.getURL === "function") {
                try {
                    const wasmUrl = api.runtime.getURL("wasm/adblock_petal_wasm_bg.wasm");
                    await fetch(wasmUrl).then(r => r.arrayBuffer()).then(bytes => WebAssembly.compile(bytes));
                } catch (_) {}
            }
            queryEngineDataFromNative();
        } catch (e) {
            console.error("[PetalAdblock] Engine init error:", e);
        } finally {
            isEngineLoading = false;
        }
    }

    function queryEngineDataFromNative() {
        if (api && api.runtime && typeof api.runtime.sendNativeMessage === "function") {
            api.runtime.sendNativeMessage(NATIVE_APP, { type: "GET_ENGINE_DATA" }, function (response) {
                if (!response) return;
                if (response.serializedEngine && response.serializedEngine.length > 0) {
                    try {
                        const binaryStr = atob(response.serializedEngine);
                        const bytes = new Uint8Array(binaryStr.length);
                        for (let i = 0; i < binaryStr.length; i++) {
                            bytes[i] = binaryStr.charCodeAt(i);
                        }
                        if (typeof AdblockEngine !== "undefined" && AdblockEngine.fromSerialized) {
                            adblockEngine = AdblockEngine.fromSerialized(bytes);
                            engineVersion = response.rulesVersion || Date.now();
                            return;
                        }
                    } catch (_) {}
                }
                if (Array.isArray(response.rules) && response.rules.length > 0) {
                    buildEngineFromFilterLists(response.rules, response.rulesVersion);
                }
            });
        }
    }

    function buildEngineFromFilterLists(rulesArray, version) {
        try {
            if (typeof AdblockEngine !== "undefined") {
                adblockEngine = new AdblockEngine(rulesArray);
                engineVersion = version || Date.now();
                if (typeof adblockEngine.serializeRaw === "function") {
                    try {
                        const serializedBytes = adblockEngine.serializeRaw();
                        let binary = "";
                        for (let i = 0; i < serializedBytes.byteLength; i++) {
                            binary += String.fromCharCode(serializedBytes[i]);
                        }
                        api.runtime.sendNativeMessage(NATIVE_APP, {
                            type: "SAVE_SERIALIZED_ENGINE",
                            serializedEngine: btoa(binary)
                        });
                    } catch (_) {}
                }
            } else {
                adblockEngine = createFastFilterEngine(rulesArray);
                engineVersion = version || Date.now();
            }
        } catch (e) {
            console.error("[PetalAdblock] Failed building filter engine:", e);
        }
    }

    function createFastFilterEngine(ruleLists) {
        const networkRules = [];
        const networkExceptions = [];
        const cosmeticHideSelectors = new Set();
        const exceptions = new Set();
        const scriptletInjections = [];

        function escapeRegExp(string) {
            return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        }

        for (const list of ruleLists) {
            if (typeof list !== "string") continue;
            const lines = list.split("\n");
            for (let line of lines) {
                line = line.trim();
                if (!line || line.startsWith("!") || line.startsWith("[")) continue;
                if (line.startsWith("@@")) {
                    const excRaw = line.substring(2);
                    const excPattern = excRaw.split("$")[0].replace(/^\|\|/, "").replace(/\^.*$/, "");
                    if (excPattern.length > 2) networkExceptions.push(excPattern);
                    continue;
                }
                if (line.includes("##")) {
                    const parts = line.split("##");
                    if (parts[1]) cosmeticHideSelectors.add(parts[1].trim());
                    continue;
                }
                if (line.includes("#@#")) {
                    const parts = line.split("#@#");
                    if (parts[1]) exceptions.add(parts[1].trim());
                    continue;
                }
                if (line.includes("#$#") || line.includes("#%#")) {
                    const parts = line.split(/#[\$%]#/);
                    if (parts[1]) scriptletInjections.push(parts[1].trim());
                    continue;
                }
                const isImportant = line.includes("$important");
                if (line.includes("$badfilter")) continue;
                const redirectMatch = line.match(/\$redirect=([a-zA-Z0-9_\-\.]+)/);
                const redirectRes = redirectMatch ? redirectMatch[1] : null;
                const cspMatch = line.match(/\$csp=([^,]+)/);
                const cspRule = cspMatch ? cspMatch[1] : null;
                const hasRemoveParam = line.includes("$removeparam");
                const isThirdPartyOnly = line.includes("$third-party") || line.includes("$3p") || line.includes(",third-party") || line.includes(",3p");
                const startsWithDomain = line.startsWith("||");
                const rawPattern = line.split("$")[0].replace(/^\|\|/, "").replace(/\^.*$/, "");

                networkRules.push({
                    raw: line,
                    pattern: rawPattern,
                    startsWithDomain: startsWithDomain,
                    hasWildcard: rawPattern.includes("*"),
                    important: isImportant,
                    redirect: redirectRes,
                    csp: cspRule,
                    removeParam: hasRemoveParam,
                    thirdPartyOnly: isThirdPartyOnly
                });
            }
        }

        function isPatternMatch(url, targetHost, rule) {
            const pat = rule.pattern;
            if (!pat || pat.length < 3) return false;
            if (rule.hasWildcard) {
                try {
                    const regex = new RegExp(pat.split("*").map(escapeRegExp).join(".*"));
                    return regex.test(url);
                } catch (_) {
                    return false;
                }
            }
            if (rule.startsWithDomain && targetHost && (targetHost === pat || targetHost.endsWith("." + pat))) {
                return true;
            }
            return url.includes(pat);
        }

        return {
            checkNetworkRequest: function (url, sourceUrl, reqType) {
                const targetHost = extractDomain(url);
                for (let j = 0; j < networkExceptions.length; j++) {
                    const exc = networkExceptions[j];
                    if (url.includes(exc) || (targetHost && (targetHost === exc || targetHost.endsWith("." + exc)))) {
                        return { matched: false, important: false, redirect: null, rewritten_url: null, csp: null, filter: null };
                    }
                }
                for (let i = 0; i < networkRules.length; i++) {
                    const r = networkRules[i];
                    if (r.removeParam) {
                        try {
                            const u = new URL(url);
                            let altered = false;
                            const paramsToRemove = ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "ttclid", "msclkid", "dclid", "yclid"];
                            for (let p = 0; p < paramsToRemove.length; p++) {
                                if (u.searchParams.has(paramsToRemove[p])) {
                                    u.searchParams.delete(paramsToRemove[p]);
                                    altered = true;
                                }
                            }
                            if (altered) {
                                return { matched: true, important: false, redirect: null, rewritten_url: u.toString(), csp: null, filter: r.raw };
                            }
                        } catch (_) {}
                    }
                    if (r.thirdPartyOnly && sourceUrl && isFirstParty(url, sourceUrl)) continue;
                    if (isPatternMatch(url, targetHost, r)) {
                        return { matched: true, important: r.important, redirect: r.redirect, rewritten_url: null, csp: r.csp, filter: r.raw };
                    }
                }
                return { matched: false, important: false, redirect: null, rewritten_url: null, csp: null, filter: null };
            },
            urlCosmeticResources: function () {
                return {
                    hide_selectors: Array.from(cosmeticHideSelectors),
                    exceptions: Array.from(exceptions),
                    injected_scriptlets: scriptletInjections,
                    generichide: false
                };
            },
            hiddenClassIdSelectors: function (classes, ids) {
                const matched = [];
                for (const c of classes) if (cosmeticHideSelectors.has("." + c)) matched.push("." + c);
                for (const id of ids) if (cosmeticHideSelectors.has("#" + id)) matched.push("#" + id);
                return matched;
            }
        };
    }

    initAdblockEngine();

    if (api.runtime && api.runtime.onMessage) {
        api.runtime.onMessage.addListener(function (message, sender, sendResponse) {
            if (!message) return;

            if (message.type === "UPDATE_BLOCKER_CONFIG") {
                // Keep blocker permanently enabled; ignore disable attempts
                isBlockerEnabled = true;
                if (typeof message.mode === "string") {
                    blockerMode = message.mode.toLowerCase();
                }
                sendResponse({ success: true });
                return true;
            }

            if (message.type === "GET_COSMETIC_RESOURCES") {
                const pageUrl = message.url || (sender.tab && sender.tab.url) || "";
                if (!adblockEngine) {
                    sendResponse({ hide_selectors: [], exceptions: [], injected_scriptlets: [], generichide: false });
                    return true;
                }
                try {
                    sendResponse(adblockEngine.urlCosmeticResources(pageUrl));
                } catch (_) {
                    sendResponse({ hide_selectors: [], exceptions: [], injected_scriptlets: [], generichide: false });
                }
                return true;
            }

            if (message.type === "BATCH_CLASS_ID_SELECTORS") {
                if (!adblockEngine) {
                    sendResponse({ hide_selectors: [] });
                    return true;
                }
                try {
                    const selectors = adblockEngine.hiddenClassIdSelectors(message.classes || [], message.ids || [], message.exceptions || []);
                    sendResponse({ hide_selectors: selectors });
                } catch (_) {
                    sendResponse({ hide_selectors: [] });
                }
                return true;
            }
        });
    }

    // Main WebRequest Interceptor (onBeforeRequest) — intercepts main_frame, sub_frame,
    // xmlhttprequest, media, and HTTP 301/302 redirect targets synchronously in memory.
    if (api.webRequest && api.webRequest.onBeforeRequest) {
        api.webRequest.onBeforeRequest.addListener(
            function (details) {
                const url = details.url;
                if (!url) return { cancel: false };

                // 1. Cold Turkey Family Filter (ALWAYS active, synchronous in-memory check)
                if (coldTurkeyEngine.shouldBlockUrl(url)) {
                    if (details.type === "main_frame") {
                        return { redirectUrl: blockedPageBaseUrl };
                    }
                    return { cancel: true };
                }

                // 2. Secondary SafeSearch Enforcement (Google & Bing)
                if (details.type === "main_frame" || details.type === "sub_frame") {
                    const safeUrl = coldTurkeyEngine.enforceSafeSearchUrl(url);
                    if (safeUrl && safeUrl !== url) {
                        return { redirectUrl: safeUrl };
                    }
                }

                // 3. Adblock-rust subresource filtering (non-main_frame only)
                if (details.type === "main_frame") return { cancel: false };
                if (url.startsWith("about:") || url.startsWith("data:") || url.startsWith("moz-extension:") || url.startsWith("chrome:")) {
                    return { cancel: false };
                }

                const sourceUrl = details.documentUrl || details.originUrl || details.initiator || "";
                const docHost = extractDomain(sourceUrl);
                if (docHost && whitelistedHosts.has(docHost)) {
                    return { cancel: false };
                }
                if (blockerMode === "standard" && sourceUrl && isFirstParty(url, sourceUrl)) {
                    return { cancel: false };
                }

                if (adblockEngine) {
                    try {
                        const result = adblockEngine.checkNetworkRequest(url, sourceUrl, details.type);
                        if (result && result.rewritten_url && result.rewritten_url !== url) {
                            return { redirectUrl: result.rewritten_url };
                        }
                        if (result && result.csp) {
                            pendingCspHeaders.set(details.requestId || url, result.csp);
                        }
                        if (result && result.matched) {
                            if (result.redirect && REDIRECT_RESOURCES[result.redirect]) {
                                return { redirectUrl: REDIRECT_RESOURCES[result.redirect] };
                            }
                            return { cancel: true };
                        }
                    } catch (_) {}
                }

                return { cancel: false };
            },
            { urls: ["<all_urls>"] },
            ["blocking"]
        );
    }

    if (api.webRequest && api.webRequest.onHeadersReceived) {
        api.webRequest.onHeadersReceived.addListener(
            function (details) {
                const key = details.requestId || details.url;
                const cspDirective = pendingCspHeaders.get(key);
                if (cspDirective) {
                    pendingCspHeaders.delete(key);
                    const responseHeaders = details.responseHeaders || [];
                    responseHeaders.push({
                        name: "Content-Security-Policy",
                        value: cspDirective
                    });
                    return { responseHeaders: responseHeaders };
                }
                return {};
            },
            { urls: ["<all_urls>"] },
            ["blocking", "responseHeaders"]
        );
    }
})();
