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
    public void testReadSimpleConfigurationEncryptionData1() throws Exception {
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
            assertEquals("saml-key", samlSecurityRealm.getPrivateKeyAlias());
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
