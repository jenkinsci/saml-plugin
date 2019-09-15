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
        assertEquals(idpMCdescriptor.doTestIdpMetadata(null).kind, Kind.ERROR);
        assertEquals(idpMCdescriptor.doTestIdpMetadata("").kind, Kind.ERROR);
        assertEquals(idpMCdescriptor.doTestIdpMetadata(" ").kind, Kind.ERROR);
        SamlPluginConfig samlPluginConfig = samlSecurityRealm.getSamlPluginConfig();
        String idpMetadata = samlPluginConfig.getIdpMetadataConfiguration().getIdpMetadata();
        assertEquals(idpMCdescriptor.doTestIdpMetadata(idpMetadata + "</none>").kind, Kind.ERROR);
        assertEquals(idpMCdescriptor.doTestIdpMetadata(idpMetadata.substring(20)).kind, Kind.ERROR);
        assertEquals(idpMCdescriptor.doTestIdpMetadata(idpMetadata).kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testKeyStore() {
        BundleKeyStore bks = new BundleKeyStore();
        bks.init();
        assertEquals(endescriptor.doTestKeyStore("", Secret.fromString(""), Secret.fromString(""), "").kind, Kind.WARNING);
        assertEquals(endescriptor.doTestKeyStore("none", Secret.fromString(""), Secret.fromString(""), "").kind, Kind.ERROR);
        assertEquals(endescriptor.doTestKeyStore(bks.getKeystorePath().substring(5), Secret.fromString(""), Secret.fromString(""), "").kind, Kind.ERROR);
        assertEquals(endescriptor.doTestKeyStore(bks.getKeystorePath().substring(5), Secret.fromString("none"), Secret.fromString(""), "").kind, Kind.ERROR);
        assertEquals(endescriptor.doTestKeyStore(bks.getKeystorePath().substring(5), Secret.fromString(bks.getKsPassword()), Secret.fromString(""), "").kind, Kind.ERROR);
        assertEquals(endescriptor.doTestKeyStore(bks.getKeystorePath().substring(5), Secret.fromString(bks.getKsPassword()), Secret.fromString("none"), "").kind, Kind.ERROR);
        assertEquals(endescriptor.doTestKeyStore(bks.getKeystorePath().substring(5), Secret.fromString(bks.getKsPassword()), Secret.fromString(bks.getKsPkPassword()), "").kind, Kind.OK);
        assertEquals(endescriptor.doTestKeyStore(bks.getKeystorePath().substring(5), Secret.fromString(bks.getKsPassword()), Secret.fromString(bks.getKsPkPassword()), "none").kind, Kind.ERROR);
        assertEquals(endescriptor.doTestKeyStore(bks.getKeystorePath().substring(5), Secret.fromString(bks.getKsPassword()), Secret.fromString(bks.getKsPkPassword()), bks.getKsPkAlias()).kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckDisplayNameAttributeName() {
        assertEquals(descriptor.doCheckDisplayNameAttributeName(null).kind, Kind.OK);
        assertEquals(descriptor.doCheckDisplayNameAttributeName("").kind, Kind.OK);
        assertEquals(descriptor.doCheckDisplayNameAttributeName(" ").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckDisplayNameAttributeName("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckGroupsAttributeName() {
        assertEquals(descriptor.doCheckGroupsAttributeName(null).kind, Kind.WARNING);
        assertEquals(descriptor.doCheckGroupsAttributeName("").kind, Kind.WARNING);
        assertEquals(descriptor.doCheckGroupsAttributeName(" ").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckGroupsAttributeName("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckUsernameAttributeName() {
        assertEquals(descriptor.doCheckUsernameAttributeName(null).kind, Kind.WARNING);
        assertEquals(descriptor.doCheckUsernameAttributeName("").kind, Kind.WARNING);
        assertEquals(descriptor.doCheckUsernameAttributeName(" ").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckUsernameAttributeName("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckAuthnContextClassRef() {
        assertEquals(advCdescriptor.doCheckAuthnContextClassRef(null).kind, Kind.OK);
        assertEquals(advCdescriptor.doCheckAuthnContextClassRef("").kind, Kind.OK);
        assertEquals(advCdescriptor.doCheckAuthnContextClassRef(" ").kind, Kind.ERROR);
        assertEquals(advCdescriptor.doCheckAuthnContextClassRef("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckEmailAttributeName() {
        assertEquals(descriptor.doCheckEmailAttributeName(null).kind, Kind.WARNING);
        assertEquals(descriptor.doCheckEmailAttributeName("").kind, Kind.WARNING);
        assertEquals(descriptor.doCheckEmailAttributeName(" ").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckEmailAttributeName("Test").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckLogoutUrl() {
        assertEquals(descriptor.doCheckLogoutUrl(null).kind, Kind.OK);
        assertEquals(descriptor.doCheckLogoutUrl("").kind, Kind.OK);
        assertEquals(descriptor.doCheckLogoutUrl(" ").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckLogoutUrl("http://example.com").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKeystorePath() {
        assertEquals(endescriptor.doCheckKeystorePath(null).kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckKeystorePath("").kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckKeystorePath(" ").kind, Kind.ERROR);
        assertEquals(endescriptor.doCheckKeystorePath("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKPrivateKeyAlias() {
        assertEquals(endescriptor.doCheckPrivateKeyAlias(null).kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckPrivateKeyAlias("").kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckPrivateKeyAlias(" ").kind, Kind.ERROR);
        assertEquals(endescriptor.doCheckPrivateKeyAlias("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKeystorePassword() {
        assertEquals(endescriptor.doCheckKeystorePassword(null).kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckKeystorePassword("").kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckKeystorePassword(" ").kind, Kind.ERROR);
        assertEquals(endescriptor.doCheckKeystorePassword("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKPrivateKeyPassword() {
        assertEquals(endescriptor.doCheckPrivateKeyPassword(null).kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckPrivateKeyPassword("").kind, Kind.WARNING);
        assertEquals(endescriptor.doCheckPrivateKeyPassword(" ").kind, Kind.ERROR);
        assertEquals(endescriptor.doCheckPrivateKeyPassword("value").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckMaximumAuthenticationLifetime() {
        assertEquals(descriptor.doCheckMaximumAuthenticationLifetime(null).kind, Kind.OK);
        assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("").kind, Kind.OK);
        assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("novalid").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckMaximumAuthenticationLifetime(Integer.MAX_VALUE + "999999").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("-1").kind, Kind.ERROR);
        assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("86400").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckMaximumSessionLifetime() {
        assertEquals(advCdescriptor.doCheckMaximumSessionLifetime(null).kind, Kind.OK);
        assertEquals(advCdescriptor.doCheckMaximumSessionLifetime("").kind, Kind.OK);
        assertEquals(advCdescriptor.doCheckMaximumSessionLifetime("novalid").kind, Kind.ERROR);
        assertEquals(advCdescriptor.doCheckMaximumSessionLifetime(Integer.MAX_VALUE + "999999").kind, Kind.ERROR);
        assertEquals(advCdescriptor.doCheckMaximumSessionLifetime("-1").kind, Kind.ERROR);
        assertEquals(advCdescriptor.doCheckMaximumSessionLifetime("86400").kind, Kind.OK);
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckSpEntityId() {
        assertEquals(advCdescriptor.doCheckSpEntityId(null).kind, Kind.OK);
        assertEquals(advCdescriptor.doCheckSpEntityId("").kind, Kind.OK);
        assertEquals(advCdescriptor.doCheckSpEntityId(" ").kind, Kind.ERROR);
        assertEquals(advCdescriptor.doCheckSpEntityId("value").kind, Kind.OK);
    }
}
