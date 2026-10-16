package com.sellerbot.ciphervault.autofill

/**
 * Turning the strings the autofill framework hands us into comparable hosts.
 *
 * The system gives us two different shapes of "where am I": a `webDomain` on
 * browser form nodes (`example.com`) and the package name of a native app
 * (`com.example.app`). Credentials are stored with a URL, so the only reliable
 * join between the two is a normalised host.
 *
 * Deliberately free of `java.net.URI`: it is surprisingly permissive about
 * input that reaches us from arbitrary app markup, and a throw here would take
 * down the fill request for a screen we could otherwise have served.
 */
object Domains {

    private const val MAX_HOST_LENGTH = 253
    private const val MAX_LABEL_LENGTH = 63

    /**
     * Normalise a URL or bare host into a comparable host.
     *
     * Lower-cases, drops scheme, credentials, port, path, a trailing dot and a
     * leading `www.`, so `https://User@example.com:443/a?b=1` and
     * `www.example.com` both reduce to `example.com`.
     *
     * @return the host, or null when [value] cannot be a host at all.
     */
    fun hostOf(value: String?): String? {
        val raw = value?.trim().orEmpty()
        if (raw.isEmpty()) return null

        // Cut the scheme. Anything after the first "/" (or "?" / "#") is path
        // or query and never part of the authority.
        val schemeAt = raw.indexOf("://")
        if (schemeAt == 0) return null // "://host" - a scheme was expected
        val withoutScheme = if (schemeAt > 0) raw.substring(schemeAt + 3) else raw
        val authority = withoutScheme
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            // userinfo carries no matching information and may contain ":" itself
            .substringAfterLast('@')

        // host:port — split on the *last* colon so an IPv6 literal is kept.
        val host = when {
            authority.startsWith("[") -> authority.substringBefore(']').trim('[', ']')
            authority.count { it == ':' } == 1 -> authority.substringBefore(':')
            else -> authority
        }.trim().lowercase().trimEnd('.')

        if (host.isEmpty()) return null
        // Spaces never appear in a host; this rejects prose like "example .com"
        // without needing to judge whether a label is plausible.
        if (host.any { it.isWhitespace() }) return null
        if (host.length > MAX_HOST_LENGTH) return null

        val withoutWww = host.removePrefix("www.")
        return withoutWww.ifEmpty { host }
    }

    /**
     * True when a host from the screen and a host from a stored credential
     * refer to the same site.
     *
     * Matching is suffix-based so a page on `login.example.com` can use the
     * credential saved for `example.com`, and vice versa. The "." in the suffix
     * is what keeps `notexample.com` from matching `example.com`.
     */
    fun matches(candidate: String?, target: String?): Boolean {
        val a = hostOf(candidate) ?: return false
        val b = hostOf(target) ?: return false
        if (a == b) return true
        return a.endsWith(".$b") || b.endsWith(".$a")
    }

    /**
     * True when the string is short enough and label-shaped enough to plausibly
     * be a host. Used to reject `null`, garbage, and absurd lengths before any
     * suffix comparison happens.
     */
    fun isValidHost(value: String?): Boolean = hostOf(value) != null

    /**
     * Whether a stored credential could have been intended for an app rather
     * than a website: `com.example.app` -> `example.app` is a heuristic, so it
     * is only consulted when there is no web domain to match against.
     */
    fun hostFromPackageName(packageName: String?): String? {
        val raw = packageName?.trim()?.lowercase().orEmpty()
        if (raw.isEmpty()) return null
        if (!raw.matches(Regex("""[a-z0-9._-]+"""))) return null
        // The last two segments of an application id are usually the site-ish
        // part (`com.example.shop` -> `example.shop`). Two segments is the
        // minimum that could be a domain; anything shorter is left alone.
        val parts = raw.split('.').filter { it.isNotEmpty() }
        if (parts.size < 2) return null
        val tail = parts.takeLast(2).joinToString(".")
        return if ('.' in tail && !tail.startsWith("www.")) tail else null
    }

    /** Guard used by the matcher: reject a host that cannot be compared. */
    internal fun isPlausibleHost(value: String?): Boolean {
        val host = hostOf(value) ?: return false
        return host.length <= MAX_HOST_LENGTH &&
            host.split('.').all { it.isNotEmpty() && it.length <= MAX_LABEL_LENGTH }
    }
}
