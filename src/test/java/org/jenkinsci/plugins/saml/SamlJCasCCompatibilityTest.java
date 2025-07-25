package org.jenkinsci.plugins.saml;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.misc.junit.jupiter.AbstractRoundTripTest;
import java.util.List;
import org.jenkinsci.plugins.saml.conf.Attribute;
import org.jenkinsci.plugins.saml.conf.AttributeEntry;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class SamlJCasCCompatibilityTest extends AbstractRoundTripTest {

    @Override
    protected void assertConfiguredAsExpected(JenkinsRule jenkinsRule, String s) {
        final SecurityRealm realm = jenkinsRule.jenkins.getSecurityRealm();
        assertNotNull(realm);
        assertInstanceOf(SamlSecurityRealm.class, realm);

        final SamlSecurityRealm samlRealm = (SamlSecurityRealm) realm;
        // Simple attributes
        assertEquals(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", samlRealm.getDisplayNameAttributeName());
        assertEquals("http://schemas.xmlsoap.org/claims/Group", samlRealm.getGroupsAttributeName());
        assertEquals(86400, samlRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("fake@mail.com", samlRealm.getEmailAttributeName());
        assertEquals("urn:mace:dir:attribute-def:uid", samlRealm.getUsernameAttributeName());
        assertEquals("none", samlRealm.getUsernameCaseConversion());
        assertEquals("http://fake.logout.url", samlRealm.getLogoutUrl());
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", samlRealm.getBinding());

        // Complex attributes
        final SamlAdvancedConfiguration advanced = samlRealm.getAdvancedConfiguration();
        assertNotNull(advanced);
        assertTrue(advanced.getForceAuthn());
        assertEquals("anotherContext", advanced.getAuthnContextClassRef());
        assertEquals("mySpEntityId", advanced.getSpEntityId());

        final SamlEncryptionData encryption = samlRealm.getEncryptionData();
        assertNotNull(encryption);
        assertEquals("/home/jdk/keystore", encryption.getKeystorePath());
        assertEquals("privatealias", encryption.getPrivateKeyAlias());

        final IdpMetadataConfiguration metadata = samlRealm.getIdpMetadataConfiguration();
        assertNotNull(metadata);
        assertEquals("http://fake.ldP.metadata.url", metadata.getUrl());
        assertEquals(2, metadata.getPeriod().longValue());
        assertThat(
                metadata.getXml(),
                containsString(
                        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"simpleSAMLphpIdpHosted\">"));
        assertThat(metadata.getXml(), containsString("<md:ContactPerson contactType=\"technical\">"));
        assertThat(metadata.getXml(), containsString("<md:GivenName>Administrator</md:GivenName>"));
        assertThat(metadata.getXml(), containsString("<md:EmailAddress>dublindev@glgroup.com</md:EmailAddress>"));

        final List<AttributeEntry> customAttributes = samlRealm.getSamlCustomAttributes();
        assertNotNull(customAttributes);
        assertEquals(2, customAttributes.size());
        assertEquals("attribute1", ((Attribute) customAttributes.get(0)).getName());
        assertEquals("display1", ((Attribute) customAttributes.get(0)).getDisplayName());
        assertEquals("attribute2", ((Attribute) customAttributes.get(1)).getName());
        assertEquals("display2", ((Attribute) customAttributes.get(1)).getDisplayName());
    }

    @Override
    protected String stringInLogExpected() {
        return "Setting class org.jenkinsci.plugins.saml.SamlSecurityRealm.emailAttributeName = fake@mail.com";
    }
}
