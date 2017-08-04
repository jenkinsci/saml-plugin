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

import hudson.security.SecurityRealm;
import hudson.util.FormValidation.Kind;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertEquals;

/**
 * Different form validation tests
 * Created by kuisathaverat on 02/08/2017.
 */
public class SamlFormValidationsTest {


    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testIdpMetadata() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doTestIdpMetadata(null).kind, Kind.ERROR);
                assertEquals(descriptor.doTestIdpMetadata("").kind, Kind.ERROR);
                assertEquals(descriptor.doTestIdpMetadata(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doTestIdpMetadata(samlSecurityRealm.getIdpMetadata() + "</none>").kind, Kind.ERROR);
                assertEquals(descriptor.doTestIdpMetadata(samlSecurityRealm.getIdpMetadata().substring(20)).kind, Kind.ERROR);
                assertEquals(descriptor.doTestIdpMetadata(samlSecurityRealm.getIdpMetadata()).kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testKeyStore() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                BundleKeyStore bks = new BundleKeyStore();
                bks.init();
                assertEquals(descriptor.doTestKeyStore(null, null, null, null).kind, Kind.WARNING);
                assertEquals(descriptor.doTestKeyStore("", null, null, null).kind, Kind.WARNING);
                assertEquals(descriptor.doTestKeyStore("", "", null, null).kind, Kind.WARNING);
                assertEquals(descriptor.doTestKeyStore("", "", "", null).kind, Kind.WARNING);
                assertEquals(descriptor.doTestKeyStore("", "", "", "").kind, Kind.WARNING);
                assertEquals(descriptor.doTestKeyStore("", "", "", "").kind, Kind.WARNING);
                assertEquals(descriptor.doTestKeyStore("none", "", "", "").kind, Kind.ERROR);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), null, "", "").kind, Kind.ERROR);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), "none", "", "").kind, Kind.ERROR);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), bks.getKsPassword(), null, "").kind, Kind.ERROR);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), bks.getKsPassword(), "none", "").kind, Kind.ERROR);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), bks.getKsPassword(), bks.getKsPkPassword(), null).kind, Kind.OK);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), bks.getKsPassword(), bks.getKsPkPassword(), "").kind, Kind.OK);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), bks.getKsPassword(), bks.getKsPkPassword(), "none").kind, Kind.ERROR);
                assertEquals(descriptor.doTestKeyStore(bks.getKeystorePath().substring(5), bks.getKsPassword(), bks.getKsPkPassword(), bks.getKsPkAlias()).kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckDisplayNameAttributeName() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckDisplayNameAttributeName(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckDisplayNameAttributeName("").kind, Kind.OK);
                assertEquals(descriptor.doCheckDisplayNameAttributeName(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckDisplayNameAttributeName("value").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckGroupsAttributeName() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckGroupsAttributeName(null).kind, Kind.WARNING);
                assertEquals(descriptor.doCheckGroupsAttributeName("").kind, Kind.WARNING);
                assertEquals(descriptor.doCheckGroupsAttributeName(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckGroupsAttributeName("value").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckUsernameAttributeName() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckUsernameAttributeName(null).kind, Kind.WARNING);
                assertEquals(descriptor.doCheckUsernameAttributeName("").kind, Kind.WARNING);
                assertEquals(descriptor.doCheckUsernameAttributeName(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckUsernameAttributeName("value").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckAuthnContextClassRef() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckAuthnContextClassRef(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckAuthnContextClassRef("").kind, Kind.OK);
                assertEquals(descriptor.doCheckAuthnContextClassRef(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckAuthnContextClassRef("value").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckEmailAttributeName() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();


                assertEquals(descriptor.doCheckEmailAttributeName(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckEmailAttributeName("").kind, Kind.OK);
                assertEquals(descriptor.doCheckEmailAttributeName(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckEmailAttributeName("value").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckLogoutUrl() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckLogoutUrl(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckLogoutUrl("").kind, Kind.OK);
                assertEquals(descriptor.doCheckLogoutUrl(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckLogoutUrl("http://example.com").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKeystorePath() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckKeystorePath(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckKeystorePath("").kind, Kind.OK);
                assertEquals(descriptor.doCheckKeystorePath(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckKeystorePath("value").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckKPrivateKeyAlias() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckKPrivateKeyAlias(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckKPrivateKeyAlias("").kind, Kind.OK);
                assertEquals(descriptor.doCheckKPrivateKeyAlias(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckKPrivateKeyAlias("value").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckMaximumAuthenticationLifetime() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckMaximumAuthenticationLifetime(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("").kind, Kind.OK);
                assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("novalid").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckMaximumAuthenticationLifetime(Integer.MAX_VALUE + "999999").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("-1").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckMaximumAuthenticationLifetime("86400").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckMaximumSessionLifetime() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckMaximumSessionLifetime(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckMaximumSessionLifetime("").kind, Kind.OK);
                assertEquals(descriptor.doCheckMaximumSessionLifetime("novalid").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckMaximumSessionLifetime(Integer.MAX_VALUE + "999999").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckMaximumSessionLifetime("-1").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckMaximumSessionLifetime("86400").kind, Kind.OK);
            }
        }
    }

    @LocalData("testReadSimpleConfigurationAdvancedConfiguration")
    @Test
    public void testCheckSpEntityId() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof SamlSecurityRealm);

        if (securityRealm instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) securityRealm;

            if (samlSecurityRealm.getDescriptor() instanceof SamlSecurityRealm.DescriptorImpl) {
                SamlSecurityRealm.DescriptorImpl descriptor = (SamlSecurityRealm.DescriptorImpl) samlSecurityRealm.getDescriptor();

                assertEquals(descriptor.doCheckSpEntityId(null).kind, Kind.OK);
                assertEquals(descriptor.doCheckSpEntityId("").kind, Kind.OK);
                assertEquals(descriptor.doCheckSpEntityId(" ").kind, Kind.ERROR);
                assertEquals(descriptor.doCheckSpEntityId("value").kind, Kind.OK);
            }
        }
    }
}
