package org.jenkinsci.plugins.saml;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.pac4j.saml.config.SAML2Configuration;
import org.pac4j.saml.replay.InMemoryReplayCacheProvider;
import org.pac4j.saml.replay.ReplayCacheProvider;

/**
 * Test for the JenkinsReplayCacheProvider extension point functionality.
 * This test validates SECURITY-3613 fix by ensuring custom replay cache providers
 * are properly loaded and used by JenkinsSAML2Client.
 */
@WithJenkins
class JenkinsReplayCacheProviderTest {

    @Test
    void testCustomReplayCacheProviderIsUsed(JenkinsRule jenkinsRule, @TempDir Path tempDir) throws IOException {
        SAML2Configuration config = new SAML2Configuration();
        JenkinsSAML2Client client = new JenkinsSAML2Client(config);
        client.setCallbackUrl("http://localhost");
        JenkinsReplayCacheProviderDefaultTest.setKeyStore(config);
        JenkinsReplayCacheProviderDefaultTest.setMetadata(config, tempDir);
        client.init();
        assertThat(
                "Custom replay cache provider should be used",
                JenkinsSAML2Client.REPLAY_CACHE,
                instanceOf(TestReplayCacheProvider.class));
        assertTrue(
                TestReplayCacheProvider.wasProviderCalled,
                "Test replay cache provider getProvider() method should have been called");
    }

    @TestExtension
    public static class TestJenkinsReplayCacheProvider implements JenkinsReplayCacheProvider {

        @Override
        public ReplayCacheProvider getProvider() {
            return new TestReplayCacheProvider();
        }
    }

    public static class TestReplayCacheProvider extends InMemoryReplayCacheProvider {

        static boolean wasProviderCalled = false;

        public TestReplayCacheProvider() {
            super();
            wasProviderCalled = true;
        }
    }
}
