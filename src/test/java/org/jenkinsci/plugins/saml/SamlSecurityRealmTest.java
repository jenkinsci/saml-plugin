package org.jenkinsci.plugins.saml;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Different configurations tests
 * Created by kuisathaverat on 30/03/2017.
 */
public class SamlSecurityRealmTest {


    @Rule
    public org.jvnet.hudson.test.JenkinsRule jenkinsRule = new org.jvnet.hudson.test.JenkinsRule();

    @LocalData
    @Test
    public void testReadSimpleConfiguration() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
            assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
            assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
            assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationLowercase() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
            assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
            assertEquals("lowercase", samlSecurityRealm.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
            assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationUppercase() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
            assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
            assertEquals("uppercase", samlSecurityRealm.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
            assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationEncryptionData() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
            assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
            assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
            assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
            assertEquals("/home/jdk/keystore", samlSecurityRealm.getKeystorePath());
            assertEquals("changeit", samlSecurityRealm.getKeystorePassword());
            assertEquals("changeit", samlSecurityRealm.getPrivateKeyPassword());

        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationAdvancedConfiguration() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
            assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
            assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
            assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
            assertEquals("/home/jdk/keystore", samlSecurityRealm.getKeystorePath());
            assertEquals("changeit", samlSecurityRealm.getKeystorePassword());
            assertEquals("changeit", samlSecurityRealm.getPrivateKeyPassword());
            assertEquals(true, samlSecurityRealm.getForceAuthn());
            assertEquals("anotherContext", samlSecurityRealm.getAuthnContextClassRef());
            assertEquals("spEntityId", samlSecurityRealm.getSpEntityId());
            assertEquals(86400, samlSecurityRealm.getMaximumSessionLifetime().longValue());
        }
    }

}
