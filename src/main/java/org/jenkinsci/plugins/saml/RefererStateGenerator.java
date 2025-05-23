package org.jenkinsci.plugins.saml;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import hudson.Util;
import java.time.Duration;
import java.util.UUID;
import java.util.logging.Logger;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.util.generator.ValueGenerator;

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.baseUrl;

/**
 * Generates relay state storing the referer for redirect after login
 */
@Restricted(NoExternalUse.class)
class RefererStateGenerator implements ValueGenerator {
    private static final Logger LOGGER = Logger.getLogger(RefererStateGenerator.class.getName());

    public static final Cache<String, String> CACHE = Caffeine.newBuilder().maximumSize(10_000).expireAfterWrite(Duration.ofMinutes(30)).build();

    public String generateValue(CallContext ctx) {
        final WebContext webContext = ctx.webContext();
        final String referer = webContext.getRequestHeader("Referer").orElse(null);
        final String from = webContext.getRequestParameter("from").orElse(null);
        final String id = UUID.randomUUID().toString();
        CACHE.put(id, calculateSafeRedirect(from, referer));
        return id;
    }

    /**
     * Check parameters "from" and "referer" to decide where is the safe URL to be redirected.
     * @param from http request "from" parameter.
     * @param referer referer header.
     * @return a safe URL to be redirected.
     */
    private static String calculateSafeRedirect(String from, String referer) {
        String redirectURL;
        String rootUrl = baseUrl();
        //noinspection PointlessNullCheck
        if (from != null && Util.isSafeToRedirectTo(from)) {
            redirectURL = from;
        } else {
            if (referer != null && (referer.startsWith(rootUrl) || Util.isSafeToRedirectTo(referer))) {
                redirectURL = referer;
            } else {
                redirectURL = rootUrl;
            }
        }
        LOGGER.fine("Safe URL redirection: " + redirectURL);
        return redirectURL;
    }

}
