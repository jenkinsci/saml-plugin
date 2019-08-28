package org.jenkinsci.plugins.saml;

import hudson.security.SecurityRealm;
import io.jenkins.plugins.casc.misc.RoundTripAbstractTest;
import org.jenkinsci.plugins.saml.conf.Attribute;
import org.jenkinsci.plugins.saml.conf.AttributeEntry;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.CoreMatchers.containsString;

public class SamlJCasCCompatibilityTest extends RoundTripAbstractTest {
    @Override
    protected void assertConfiguredAsExpected(RestartableJenkinsRule restartableJenkinsRule, String s) {
        final SecurityRealm realm = restartableJenkinsRule.j.jenkins.getSecurityRealm();
        assertTrue("The Security Realm should not be null", realm != null);
        assertTrue("The Security Realm should be SamlSecurityRealm", realm instanceof SamlSecurityRealm);

        final SamlSecurityRealm samlRealm = (SamlSecurityRealm)realm;
        // Simple attributes
        assertEquals(String.format("Wrong Display Name Attribute Name value. Expected %s but retrieved %s", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", samlRealm.getDisplayNameAttributeName()), "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", samlRealm.getDisplayNameAttributeName());
        assertEquals(String.format("Wrong Group Attribute value. Expected %s but retrieved %s", "http://schemas.xmlsoap.org/claims/Group", samlRealm.getGroupsAttributeName()), "http://schemas.xmlsoap.org/claims/Group", samlRealm.getGroupsAttributeName());
        assertEquals(String.format("Wrong Maximum Authentication Lifetime value. Expected %d but retrieved %d", 86400, samlRealm.getMaximumAuthenticationLifetime()), 86400, samlRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals(String.format("Wrong Email Attribute value. Expected %s but retrieved %s", "fake@mail.com", samlRealm.getEmailAttributeName()), "fake@mail.com", samlRealm.getEmailAttributeName());
        assertEquals(String.format("Wrong Username Attribute  value. Expected %s but retrieved %s", "urn:mace:dir:attribute-def:uid", samlRealm.getUsernameAttributeName()), "urn:mace:dir:attribute-def:uid", samlRealm.getUsernameAttributeName());
        assertEquals(String.format("Wrong Username Case Conversion value. Expected %s but retrieved %s", "none", samlRealm.getUsernameCaseConversion()), "none", samlRealm.getUsernameCaseConversion());
        assertEquals(String.format("Wrong Logout URL value. Expected %s but retrieved %s", "http://fake.logout.url", samlRealm.getLogoutUrl()), "http://fake.logout.url", samlRealm.getLogoutUrl());
        assertEquals(String.format("Wrong Data Binding Method value. Expected %s but retrieved %s", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", samlRealm.getBinding()), "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", samlRealm.getBinding());

        // Complex attributes
        final SamlAdvancedConfiguration advanced = samlRealm.getAdvancedConfiguration();
        assertTrue("The Advanced Configuration should not be null", advanced != null);
        assertTrue("Wrong Force Authentication value in Advanced Configuration. It should be forced", advanced.getForceAuthn());
        assertEquals(String.format("Wrong Authentication Context value in Advanced Configuration. Expected %s but retrieved %s", "anotherContext", advanced.getAuthnContextClassRef()),"anotherContext", advanced.getAuthnContextClassRef());
        assertEquals(String.format("Wrong SSP Entity ID value in Advanced Configuration. Expected %s but retrieved %s", "mySpEntityId", advanced.getSpEntityId()), "mySpEntityId", advanced.getSpEntityId());

        final SamlEncryptionData encryption = samlRealm.getEncryptionData();
        assertTrue("The Encryption Configuration should not be null", encryption != null);
        assertEquals(String.format("Wrong Keystore Path value in Encryption Configuration. Expected %s but retrieved %s", "/home/jdk/keystore", encryption.getKeystorePath()),"/home/jdk/keystore", encryption.getKeystorePath());
        assertEquals(String.format("Wrong Private Key Alias value in Encryption Configuration. Expected %s but retrieved %s", "privatealias", encryption.getPrivateKeyAlias()),"privatealias", encryption.getPrivateKeyAlias());

        final IdpMetadataConfiguration metadata = samlRealm.getIdpMetadataConfiguration();
        assertTrue("The IdP Metadata should not be null", metadata != null);
        assertEquals(String.format("Wrong IdP Metadata URL value in IdP Metadata. Expected %s but retrieved %s", "http://fake.ldP.metadata.url", metadata.getUrl()), "http://fake.ldP.metadata.url", metadata.getUrl());
        assertEquals(String.format("Wrong Refresh Period value in IdP Metadata. Expected %d but retrieved %d", 2, metadata.getPeriod()), 2, metadata.getPeriod().longValue());
        assertThat("Wrong Metadata value in IdP Metadata", metadata.getXml(), containsString("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"simpleSAMLphpIdpHosted\">"));
        assertThat("Wrong Metadata value in IdP Metadata", metadata.getXml(), containsString("<md:ContactPerson contactType=\"technical\">"));
        assertThat("Wrong Metadata value in IdP Metadata", metadata.getXml(), containsString("<md:GivenName>Administrator</md:GivenName>"));
        assertThat("Wrong Metadata value in IdP Metadata", metadata.getXml(), containsString("<md:EmailAddress>dublindev@glgroup.com</md:EmailAddress>"));

        final List<AttributeEntry> customAttributes = samlRealm.getSamlCustomAttributes();
        assertTrue("The Custom Attributes should not be null", customAttributes != null);
        assertEquals(String.format("There should be 2 custom attributes but got %d", customAttributes.size()), 2, customAttributes.size());
        assertEquals(String.format("Wrong Attribute Name value in the first custom attribute. Expected %s but retrieved %s", "attribute1", ((Attribute)customAttributes.get(0)).getName()),"attribute1", ((Attribute)customAttributes.get(0)).getName());
        assertEquals(String.format("Wrong Display Name in user properties value in the first custom attribute. Expected %s but retrieved %s", "display1", ((Attribute)customAttributes.get(0)).getDisplayName()), "display1", ((Attribute)customAttributes.get(0)).getDisplayName());
        assertEquals(String.format("Wrong Attribute Name value in the second custom attribute. Expected %s but retrieved %s", "attribute2", ((Attribute)customAttributes.get(1)).getName()),"attribute2", ((Attribute)customAttributes.get(1)).getName());
        assertEquals(String.format("Wrong Display Name in user properties value in the second custom attribute. Expected %s but retrieved %s", "display2", ((Attribute)customAttributes.get(1)).getDisplayName()), "display2", ((Attribute)customAttributes.get(1)).getDisplayName());
    }

    @Override
    protected String stringInLogExpected() {
        return "Setting class org.jenkinsci.plugins.saml.SamlSecurityRealm. emailAttributeName = fake@mail.com";
    }
}
