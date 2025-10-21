package org.jenkinsci.plugins.saml;

import hudson.ExtensionList;
import java.util.logging.Logger;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import org.pac4j.saml.replay.InMemoryReplayCacheProvider;
import org.pac4j.saml.replay.ReplayCacheProvider;

/**
 * This override of the base {@link SAML2Client} is needed to fix SECURITY-3613, by setting
 * up a replay cache which is static to all client instances.
 */
public class JenkinsSAML2Client extends SAML2Client {

    private static final Logger LOGGER = Logger.getLogger(JenkinsSAML2Client.class.getName());

    static final ReplayCacheProvider REPLAY_CACHE = getProvider();

    public JenkinsSAML2Client(SAML2Configuration config) {
        super(config);
    }

    @Override
    protected void initSAMLReplayCache(boolean forceReinit) {
        replayCache = REPLAY_CACHE;
    }

    private static ReplayCacheProvider getProvider() {
        var providers = ExtensionList.lookup(JenkinsReplayCacheProvider.class);
        if (providers.isEmpty()) {
            // Default if no extension is registered
            return new InMemoryReplayCacheProvider();
        }
        if (providers.size() > 1) {
            LOGGER.fine(() -> String.format(
                    "There is more than one JenkinsReplayCacheProvider extension registered. "
                            + "Picking [%s] as it's first one in the extensions list.",
                    providers.get(0).getClass().getName()));
        }
        return providers.get(0).getProvider();
    }
}
