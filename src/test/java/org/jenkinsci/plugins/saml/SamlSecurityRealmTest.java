/* Licensed to Jenkins CI under one or more contributor license
agreements.  See the NOTICE file distributed with this work
for additional information regarding copyright ownership.
Jenkins CI licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the
License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License. */

package org.jenkinsci.plugins.saml;

import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerResponse;
import org.mockito.Mockito;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

/**
 * Different configurations tests
 * Created by kuisathaverat on 30/03/2017.
 */
public class SamlSecurityRealmTest {


    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

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
            assertEquals("urn:mace:dir:attribute-def:mail", samlSecurityRealm.getEmailAttributeName());
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

    @Test
    public void metadataWrapper() throws IOException, ServletException {
        String metadata = IOUtils.toString(this.getClass().getClassLoader().getResourceAsStream("org/jenkinsci/plugins/saml/SamlSecurityRealmTest/metadataWrapper/metadata.xml"));
        SamlSecurityRealm samlSecurity = new SamlSecurityRealm(metadata, "displayName", "groups", 10000, "uid", "email", "/logout", null, null, null);
        jenkinsRule.jenkins.setSecurityRealm(samlSecurity);
        SamlSPMetadataWrapper samlSPMetadataWrapper = new SamlSPMetadataWrapper(samlSecurity.getSamlPluginConfig(), null, null);
        HttpResponse process = samlSPMetadataWrapper.process();
        StaplerResponse mockResponse = Mockito.mock(StaplerResponse.class);
        StringWriter stringWriter = new StringWriter();
        when(mockResponse.getWriter()).thenReturn(new PrintWriter(stringWriter));
        process.generateResponse(null, mockResponse, null);
        String result = stringWriter.toString();
        // Some random checks as the full XML comparison fails because of reformatting on processing
        assertThat(result, containsString("EntityDescriptor"));
        assertThat(result, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"));
        assertThat(result, containsString("<ds:X509Certificate>"));
    }
}
