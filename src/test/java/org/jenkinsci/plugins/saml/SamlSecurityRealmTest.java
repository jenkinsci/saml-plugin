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

import org.acegisecurity.GrantedAuthority;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertEquals;

/**
 * Different configurations tests
 * Created by kuisathaverat on 30/03/2017.
 */
public class SamlSecurityRealmTest {


    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    private SamlSecurityRealm samlSecurityRealm;

    @Before
    public void start() {
        if (jenkinsRule.getInstance().getSecurityRealm() instanceof SamlSecurityRealm) {
            samlSecurityRealm = (SamlSecurityRealm) jenkinsRule.getInstance().getSecurityRealm();
        } else {
            throw new RuntimeException("The security Realm it is not correct");
        }
    }


    @LocalData
    @Test
    public void testReadSimpleConfiguration() {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:mail", samlSecurityRealm.getEmailAttributeName());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationLowercase() {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("lowercase", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationUppercase() {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("uppercase", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadata().startsWith("<?xml version"));
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationEncryptionData() {
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

    @LocalData
    @Test
    public void testReadSimpleConfigurationAdvancedConfiguration() {
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

    @LocalData("testHugeNumberOfUsers")
    @Test(timeout = 15000)
    public void testLoadGroupByGroupname() {
        assertEquals(samlSecurityRealm.loadGroupByGroupname("role500", true).getName(), "role500");
    }

    @LocalData("testHugeNumberOfUsers")
    @Test(timeout = 5000)
    public void testLoadUserByUsername() {
        assertEquals(samlSecurityRealm.loadUserByUsername("tesla").getUsername(), "tesla");
    }

    @LocalData("testReadSimpleConfiguration")
    @Test
    public void testGetters() {
        SamlPluginConfig samlPluginConfig = new SamlPluginConfig(samlSecurityRealm.getDisplayNameAttributeName(),
                samlSecurityRealm.getGroupsAttributeName(),
                samlSecurityRealm.getMaximumAuthenticationLifetime(),
                samlSecurityRealm.getEmailAttributeName(),
                samlSecurityRealm.getIdpMetadata(),
                samlSecurityRealm.getUsernameCaseConversion(),
                samlSecurityRealm.getUsernameAttributeName(),
                samlSecurityRealm.getLogoutUrl(),
                samlSecurityRealm.getEncryptionData(),
                samlSecurityRealm.getAdvancedConfiguration());
        assertEquals(samlPluginConfig.toString().equals(samlSecurityRealm.getSamlPluginConfig().toString()), true);

        assertEquals(new SamlAdvancedConfiguration(null,null,null, null).toString().contains("SamlAdvancedConfiguration"),true);
        assertEquals(new SamlAdvancedConfiguration(true,null,null, null).toString().contains("SamlAdvancedConfiguration"),true);
        assertEquals(new SamlAdvancedConfiguration(true,"","", 1).toString().contains("SamlAdvancedConfiguration"),true);

        SamlGroupAuthority authority = new SamlGroupAuthority("role001");
        assertEquals(authority.toString().equals("role001"),true);

        SamlUserDetails userDetails = new SamlUserDetails("tesla",new GrantedAuthority[]{authority});
        assertEquals(userDetails.toString().contains("tesla") && userDetails.toString().contains("role001"), true);

//        SamlAuthenticationToken token = new SamlAuthenticationToken(userDetails, );
    }
}
