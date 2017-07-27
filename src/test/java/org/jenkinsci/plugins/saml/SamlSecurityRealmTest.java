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

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertEquals;

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
            org.jenkinsci.plugins.saml.SamlPluginConfig samlPluginConfig = samlSecurityRealm.getSamlPluginConfig();
            assertEquals("urn:mace:dir:attribute-def:displayName", samlPluginConfig.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlPluginConfig.getGroupsAttributeName());
            assertEquals(86400, samlPluginConfig.getMaximumAuthenticationLifetime().longValue());
            assertEquals("none", samlPluginConfig.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:mail", samlPluginConfig.getEmailAttributeName());
            assertEquals("urn:mace:dir:attribute-def:uid", samlPluginConfig.getUsernameAttributeName());
            assertEquals(true, samlPluginConfig.getIdpMetadata().startsWith("<?xml version"));
        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationLowercase() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            org.jenkinsci.plugins.saml.SamlPluginConfig samlPluginConfig = samlSecurityRealm.getSamlPluginConfig();
            assertEquals("urn:mace:dir:attribute-def:displayName", samlPluginConfig.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlPluginConfig.getGroupsAttributeName());
            assertEquals(86400, samlPluginConfig.getMaximumAuthenticationLifetime().longValue());
            assertEquals("lowercase", samlPluginConfig.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlPluginConfig.getUsernameAttributeName());
            assertEquals(true, samlPluginConfig.getIdpMetadata().startsWith("<?xml version"));
        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationUppercase() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            org.jenkinsci.plugins.saml.SamlPluginConfig samlPluginConfig = samlSecurityRealm.getSamlPluginConfig();
            assertEquals("urn:mace:dir:attribute-def:displayName", samlPluginConfig.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlPluginConfig.getGroupsAttributeName());
            assertEquals(86400, samlPluginConfig.getMaximumAuthenticationLifetime().longValue());
            assertEquals("uppercase", samlPluginConfig.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlPluginConfig.getUsernameAttributeName());
            assertEquals(true, samlPluginConfig.getIdpMetadata().startsWith("<?xml version"));
        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationEncryptionData() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            org.jenkinsci.plugins.saml.SamlPluginConfig samlPluginConfig = samlSecurityRealm.getSamlPluginConfig();
            assertEquals("urn:mace:dir:attribute-def:displayName", samlPluginConfig.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlPluginConfig.getGroupsAttributeName());
            assertEquals(86400, samlPluginConfig.getMaximumAuthenticationLifetime().longValue());
            assertEquals("none", samlPluginConfig.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlPluginConfig.getUsernameAttributeName());
            assertEquals(true, samlPluginConfig.getIdpMetadata().startsWith("<?xml version"));
            assertEquals("/home/jdk/keystore", samlPluginConfig.getKeystorePath());
            assertEquals("changeit", samlPluginConfig.getKeystorePassword());
            assertEquals("changeit", samlPluginConfig.getPrivateKeyPassword());

        }
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationAdvancedConfiguration() throws Exception {
        hudson.security.SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;
            org.jenkinsci.plugins.saml.SamlPluginConfig samlPluginConfig = samlSecurityRealm.getSamlPluginConfig();
            assertEquals("urn:mace:dir:attribute-def:displayName", samlPluginConfig.getDisplayNameAttributeName());
            assertEquals("urn:mace:dir:attribute-def:groups", samlPluginConfig.getGroupsAttributeName());
            assertEquals(86400, samlPluginConfig.getMaximumAuthenticationLifetime().longValue());
            assertEquals("none", samlPluginConfig.getUsernameCaseConversion());
            assertEquals("urn:mace:dir:attribute-def:uid", samlPluginConfig.getUsernameAttributeName());
            assertEquals(true, samlPluginConfig.getIdpMetadata().startsWith("<?xml version"));
            assertEquals("/home/jdk/keystore", samlPluginConfig.getKeystorePath());
            assertEquals("changeit", samlPluginConfig.getKeystorePassword());
            assertEquals("changeit", samlPluginConfig.getPrivateKeyPassword());
            assertEquals(true, samlPluginConfig.getForceAuthn());
            assertEquals("anotherContext", samlPluginConfig.getAuthnContextClassRef());
            assertEquals("spEntityId", samlPluginConfig.getSpEntityId());
            assertEquals(86400, samlPluginConfig.getMaximumSessionLifetime().longValue());
        }
    }
}
