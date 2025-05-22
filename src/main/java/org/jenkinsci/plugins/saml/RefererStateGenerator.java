package org.jenkinsci.plugins.saml;

import hudson.Util;
import java.util.logging.Logger;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.util.generator.ValueGenerator;

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.baseUrl;

/**
 * Generates relay state storing the referer for redirect after login
 */
// TODO Store the actual URL in a cache and only provide a reference to not exceed 80 bytes of relay state
class RefererStateGenerator implements ValueGenerator {
    private static final Logger LOGGER = Logger.getLogger(RefererStateGenerator.class.getName());

    public String generateValue(CallContext ctx) {
        final WebContext webContext = ctx.webContext();
        final String referer = webContext.getRequestHeader("Referer").orElse(null);

        final String from = webContext.getRequestParameter("from").orElse(null);
        return calculateSafeRedirect(from, referer);
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
