package org.jenkinsci.plugins.saml;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;

import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.pac4j.saml.config.SAML2Configuration;
import org.pac4j.saml.replay.InMemoryReplayCacheProvider;

/**
 * Test to verify that the default InMemoryReplayCacheProvider is used
 * when no JenkinsReplayCacheProvider extension is registered.
 * This test validates the default behavior in the SECURITY-3613 fix.
 */
@WithJenkins
class JenkinsReplayCacheProviderDefaultTest {

    @Test
    void testDefaultReplayCacheProviderIsUsed(JenkinsRule jenkinsRule) {
        SAML2Configuration config = new SAML2Configuration();
        JenkinsSAML2Client client = new JenkinsSAML2Client(config);
        client.setCallbackUrl("http://localhost");
        setKeyStore(config);
        client.init();
        assertThat(
                "Default InMemoryReplayCacheProvider should be used when no extension is registered",
                JenkinsSAML2Client.REPLAY_CACHE,
                instanceOf(InMemoryReplayCacheProvider.class));
    }

    static void setKeyStore(SAML2Configuration config) {
        BundleKeyStore keyStore = new BundleKeyStore();
        if (!keyStore.isValid()) {
            keyStore.init();
        }
        config.setKeystorePath(keyStore.getKeystorePath());
        config.setKeystorePassword(keyStore.getKsPassword());
        config.setPrivateKeyPassword(keyStore.getKsPkPassword());
        config.setKeyStoreAlias(keyStore.getKsPkAlias());
    }
}
