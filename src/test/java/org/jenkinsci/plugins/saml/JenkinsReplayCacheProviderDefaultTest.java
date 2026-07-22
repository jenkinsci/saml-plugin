package org.jenkinsci.plugins.saml;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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
    void testDefaultReplayCacheProviderIsUsed(JenkinsRule jenkinsRule, @TempDir Path tempDir) throws IOException {
        SAML2Configuration config = new SAML2Configuration();
        JenkinsSAML2Client client = new JenkinsSAML2Client(config);
        client.setCallbackUrl("http://localhost");
        setKeyStore(config);
        setMetadata(config, tempDir);
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

    static void setMetadata(SAML2Configuration config, Path tempDir) throws IOException {
        Path idpMetadata = tempDir.resolve("idp-metadata.xml");
        Files.copy(
                JenkinsReplayCacheProviderDefaultTest.class.getResourceAsStream(
                        "/org/jenkinsci/plugins/saml/OpenSamlWrapperTest/metadataWrapper/metadata.xml"),
                idpMetadata,
                StandardCopyOption.REPLACE_EXISTING);
        config.setIdentityProviderMetadataResource(new SamlFileResource(idpMetadata.toString()));
        config.setForceServiceProviderMetadataGeneration(true);
        config.setServiceProviderMetadataResource(
                new SamlFileResource(tempDir.resolve("sp-metadata.xml").toString()));
    }
}
