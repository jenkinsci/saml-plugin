package org.jenkinsci.plugins.saml;

import hudson.ExtensionPoint;
import org.pac4j.saml.replay.ReplayCacheProvider;

/**
 * {@link ReplayCacheProvider} being an interface suggests that there can be different providers, so this abstraction
 * will allow to switch to another provider implementation if needed.
 */
public interface JenkinsReplayCacheProvider extends ExtensionPoint {

    /**
     * Returns the {@link ReplayCacheProvider} to be used by {@link JenkinsSAML2Client}
     */
    ReplayCacheProvider getProvider();
}
