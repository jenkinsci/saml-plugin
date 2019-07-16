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

import hudson.util.FormValidation.Kind;
import hudson.util.Secret;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertEquals;

/**
 * Different form validation tests
 */
public class SamlFormValidationsTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    private SamlSecurityRealm samlSecurityRealm;
    private SamlSecurityRealm.DescriptorImpl descriptor;
    private IdpMetadataConfiguration.DescriptorImpl idpMCdescriptor;
    private SamlAdvancedConfiguration.DescriptorImpl advCdescriptor;
    private SamlEncryptionData.DescriptorImpl endescriptor;

    @Before
    public void start() {
        if (jenkinsRule.getInstance().getSecurityRealm() instanceof SamlSecurityRealm) {
            samlSecurityRealm = (SamlSecurityRealm) jenkinsRule.getInstance().getSecurityRealm();
        } else {
            throw new RuntimeException("The security Realm it is not correct");
        }
        if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
            descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();
        } else {
            throw new RuntimeException("The security Realm it is not correct");
        }
        if (samlSecurityRealm.getAdvancedConfiguration().getDescriptor() instanceof SamlAdvancedConfiguration.DescriptorImpl) {
            advCdescriptor = (SamlAdvancedConfiguration.DescriptorImpl) samlSecurityRealm.getAdvancedConfiguration().getDescriptor();
        } else {
            throw new RuntimeException("The security Realm it is not correct");
        }
        if (samlSecurityRealm.getIdpMetadataConfiguration().getDescriptor() instanceof IdpMetadataConfiguration.DescriptorImpl) {
            idpMCdescriptor = (IdpMetadataConfiguration.DescriptorImpl) samlSecurityRealm.getIdpMetadataConfiguration().getDescriptor() ;
        } else {
            throw new RuntimeException("The security Realm it is not correct");
        }
        if (samlSecurityRealm.getEncryptionData().getDescriptor() instanceof SamlEncryptionData.DescriptorImpl) {
            endescriptor = (SamlEncryptionData.DescriptorImpl) samlSecurityRealm.getEncryptionData().getDescriptor();
        } else {
            throw new RuntimeException("The security Realm it is not correct");
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testIdpMetadata() throws Exception {
        assertEquals(Kind.ERROR, idpMCdescriptor.doTestIdpMetadata(null).kind );
        assertEquals(Kind.ERROR, idpMCdescriptor.doTestIdpMetadata("").kind);
        assertEquals(Kind.ERROR, idpMCdescriptor.doTestIdpMetadata(" ").kind);
        SamlPluginConfig samlPluginConfig = samlSecurityRealm.getSamlPluginConfig();
        String idpMetadata = samlPluginConfig.getIdpMetadataConfiguration().getIdpMetadata();
        assertEquals(Kind.ERROR, idpMCdescriptor.doTestIdpMetadata(idpMetadata + "</none>").kind);
        assertEquals(Kind.ERROR, idpMCdescriptor.doTestIdpMetadata(idpMetadata.substring(20)).kind);
        assertEquals(Kind.OK, idpMCdescriptor.doTestIdpMetadata(idpMetadata).kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testKeyStore() throws Exception {
        BundleKeyStore bks = new BundleKeyStore();
        bks.init();
        assertEquals(Kind.WARNING, endescriptor.doTestKeyStore("", Secret.fromString(""), Secret.fromString(""), "").kind);
        assertEquals(Kind.ERROR, endescriptor.doTestKeyStore("none", Secret.fromString(""), Secret.fromString(""), "").kind);
        assertEquals(Kind.ERROR, endescriptor.doTestKeyStore(bks.getKeystorePath().substring(bks.getKeystorePath().indexOf(":")+1), Secret.fromString(""), Secret.fromString(""), "").kind);
        assertEquals(Kind.ERROR, endescriptor.doTestKeyStore(bks.getKeystorePath().substring(bks.getKeystorePath().indexOf(":")+1), Secret.fromString("none"), Secret.fromString(""), "").kind);
        assertEquals(Kind.ERROR, endescriptor.doTestKeyStore(bks.getKeystorePath().substring(bks.getKeystorePath().indexOf(":")+1), Secret.fromString(bks.getKsPassword()), Secret.fromString(""), "").kind);
        assertEquals(Kind.ERROR, endescriptor.doTestKeyStore(bks.getKeystorePath().substring(bks.getKeystorePath().indexOf(":")+1), Secret.fromString(bks.getKsPassword()), Secret.fromString("none"), "").kind);
        assertEquals(Kind.OK, endescriptor.doTestKeyStore(bks.getKeystorePath().substring(bks.getKeystorePath().indexOf(":")+1), Secret.fromString(bks.getKsPassword()), Secret.fromString(bks.getKsPkPassword()), "").kind);
        assertEquals(Kind.ERROR, endescriptor.doTestKeyStore(bks.getKeystorePath().substring(bks.getKeystorePath().indexOf(":")+1), Secret.fromString(bks.getKsPassword()), Secret.fromString(bks.getKsPkPassword()), "none").kind);
        assertEquals(Kind.OK, endescriptor.doTestKeyStore(bks.getKeystorePath().substring(bks.getKeystorePath().indexOf(":")+1), Secret.fromString(bks.getKsPassword()), Secret.fromString(bks.getKsPkPassword()), bks.getKsPkAlias()).kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckDisplayNameAttributeName() throws Exception {
        assertEquals(Kind.OK, descriptor.doCheckDisplayNameAttributeName(null).kind);
        assertEquals(Kind.OK, descriptor.doCheckDisplayNameAttributeName("").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckDisplayNameAttributeName(" ").kind);
        assertEquals(Kind.OK, descriptor.doCheckDisplayNameAttributeName("value").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckGroupsAttributeName() throws Exception {
        assertEquals(Kind.WARNING, descriptor.doCheckGroupsAttributeName(null).kind);
        assertEquals(Kind.WARNING, descriptor.doCheckGroupsAttributeName("").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckGroupsAttributeName(" ").kind);
        assertEquals(Kind.OK, descriptor.doCheckGroupsAttributeName("value").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckUsernameAttributeName() throws Exception {
        assertEquals(Kind.WARNING, descriptor.doCheckUsernameAttributeName(null).kind);
        assertEquals(Kind.WARNING, descriptor.doCheckUsernameAttributeName("").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckUsernameAttributeName(" ").kind);
        assertEquals(Kind.OK, descriptor.doCheckUsernameAttributeName("value").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckAuthnContextClassRef() throws Exception {
        assertEquals(Kind.OK, advCdescriptor.doCheckAuthnContextClassRef(null).kind);
        assertEquals(Kind.OK, advCdescriptor.doCheckAuthnContextClassRef("").kind);
        assertEquals(Kind.ERROR, advCdescriptor.doCheckAuthnContextClassRef(" ").kind);
        assertEquals(Kind.OK, advCdescriptor.doCheckAuthnContextClassRef("value").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckEmailAttributeName() throws Exception {
        assertEquals(Kind.OK, descriptor.doCheckEmailAttributeName(null).kind);
        assertEquals(Kind.OK, descriptor.doCheckEmailAttributeName("").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckEmailAttributeName(" ").kind);
        assertEquals(Kind.OK, descriptor.doCheckEmailAttributeName("Test@example.com").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckLogoutUrl() throws Exception {
        assertEquals(Kind.OK, descriptor.doCheckLogoutUrl(null).kind);
        assertEquals(Kind.OK, descriptor.doCheckLogoutUrl("").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckLogoutUrl(" ").kind);
        assertEquals(Kind.OK, descriptor.doCheckLogoutUrl("http://example.com").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKeystorePath() throws Exception {
        assertEquals(Kind.OK, endescriptor.doCheckKeystorePath(null).kind);
        assertEquals(Kind.OK, endescriptor.doCheckKeystorePath("").kind);
        assertEquals(Kind.ERROR, endescriptor.doCheckKeystorePath(" ").kind);
        assertEquals(Kind.OK, endescriptor.doCheckKeystorePath("value").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKPrivateKeyAlias() throws Exception {
        assertEquals(Kind.OK, endescriptor.doCheckPrivateKeyAlias(null).kind);
        assertEquals(Kind.OK, endescriptor.doCheckPrivateKeyAlias("").kind);
        assertEquals(Kind.ERROR, endescriptor.doCheckPrivateKeyAlias(" ").kind);
        assertEquals(Kind.OK, endescriptor.doCheckPrivateKeyAlias("value").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckMaximumAuthenticationLifetime() throws Exception {
        assertEquals(Kind.OK, descriptor.doCheckMaximumAuthenticationLifetime(null).kind);
        assertEquals(Kind.OK, descriptor.doCheckMaximumAuthenticationLifetime("").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckMaximumAuthenticationLifetime("novalid").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckMaximumAuthenticationLifetime(Integer.MAX_VALUE + "999999").kind);
        assertEquals(Kind.ERROR, descriptor.doCheckMaximumAuthenticationLifetime("-1").kind);
        assertEquals(Kind.OK, descriptor.doCheckMaximumAuthenticationLifetime("86400").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckMaximumSessionLifetime() throws Exception {
        assertEquals(Kind.OK, advCdescriptor.doCheckMaximumSessionLifetime(null).kind);
        assertEquals(Kind.OK, advCdescriptor.doCheckMaximumSessionLifetime("").kind);
        assertEquals(Kind.ERROR, advCdescriptor.doCheckMaximumSessionLifetime("novalid").kind);
        assertEquals(Kind.ERROR, advCdescriptor.doCheckMaximumSessionLifetime(Integer.MAX_VALUE + "999999").kind);
        assertEquals(Kind.ERROR, advCdescriptor.doCheckMaximumSessionLifetime("-1").kind);
        assertEquals(Kind.OK, advCdescriptor.doCheckMaximumSessionLifetime("86400").kind);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckSpEntityId() throws Exception {
        assertEquals(Kind.OK, advCdescriptor.doCheckSpEntityId(null).kind);
        assertEquals(Kind.OK, advCdescriptor.doCheckSpEntityId("").kind);
        assertEquals(Kind.ERROR, advCdescriptor.doCheckSpEntityId(" ").kind);
        assertEquals(Kind.OK, advCdescriptor.doCheckSpEntityId("value").kind);
    }
}
