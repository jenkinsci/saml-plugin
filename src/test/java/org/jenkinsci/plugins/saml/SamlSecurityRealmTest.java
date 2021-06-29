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

import hudson.XmlFile;
import hudson.security.AuthorizationStrategy;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.LogRecord;
import org.acegisecurity.GrantedAuthority;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.jvnet.hudson.test.recipes.LocalData;
import org.jvnet.hudson.test.recipes.WithTimeout;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.hamcrest.MatcherAssert.assertThat;
import org.jvnet.hudson.test.Issue;
import org.pac4j.saml.profile.SAML2Profile;

import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;


/**
 * Different configurations tests
 */
public class SamlSecurityRealmTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Rule
    public LoggerRule logs = new LoggerRule().record(SamlSecurityRealm.class, Level.WARNING);

    private SamlSecurityRealm samlSecurityRealm;

    @Before
    public void start() {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertThat("The security realm should be saml", securityRealm, instanceOf(SamlSecurityRealm.class));
        samlSecurityRealm = (SamlSecurityRealm) securityRealm;
        Logger logger = Logger.getLogger("org.jenkinsci.plugins.saml");
        logger.setLevel(Level.FINEST);
        LogManager.getLogManager().addLogger(logger);
        Logger logger1 = Logger.getLogger("org.pac4j");
        logger1.setLevel(Level.FINEST);
        LogManager.getLogManager().addLogger(logger1);
    }

    @LocalData
    @Test
    public void testReadSimpleConfiguration() throws IOException {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:mail", samlSecurityRealm.getEmailAttributeName());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        assertEquals(SAML2_REDIRECT_BINDING_URI, samlSecurityRealm.getBinding());
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationHTTPPost() throws IOException {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:mail", samlSecurityRealm.getEmailAttributeName());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        assertEquals(SAML2_POST_BINDING_URI, samlSecurityRealm.getBinding());
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationLowercase() throws Exception {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("lowercase", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        assertEquals(SAML2_REDIRECT_BINDING_URI, samlSecurityRealm.getBinding());
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationUppercase() throws Exception {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("uppercase", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        assertEquals(SAML2_REDIRECT_BINDING_URI, samlSecurityRealm.getBinding());
    }

    @Issue("JENKINS-46007")
    @LocalData
    @Test
    public void testReadSimpleConfigurationEncryptionData() throws Exception {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        assertEquals("/home/jdk/keystore", samlSecurityRealm.getEncryptionData().getKeystorePath());
        assertEquals(Secret.fromString("changeitks"), samlSecurityRealm.getEncryptionData().getKeystorePassword());
        assertEquals(Secret.fromString("changeitpk"), samlSecurityRealm.getEncryptionData().getPrivateKeyPassword());
        assertEquals(SAML2_REDIRECT_BINDING_URI, samlSecurityRealm.getBinding());
        jenkinsRule.jenkins.setAuthorizationStrategy(AuthorizationStrategy.UNSECURED); // since we cannot actually log in during the test
        jenkinsRule.submit(jenkinsRule.createWebClient().goTo("configureSecurity").getFormByName("config"));
        samlSecurityRealm = (SamlSecurityRealm) jenkinsRule.jenkins.getSecurityRealm();
        assertEquals(Secret.fromString("changeitks"), samlSecurityRealm.getEncryptionData().getKeystorePassword());
        assertEquals(Secret.fromString("changeitpk"), samlSecurityRealm.getEncryptionData().getPrivateKeyPassword());
        assertThat(new XmlFile(new File(jenkinsRule.jenkins.root, "config.xml")).asString(), not(containsString("changeit")));
        assertEquals(false, samlSecurityRealm.getEncryptionData().isForceSignRedirectBindingAuthnRequest());
    }

    @LocalData
    @Test
    public void testReadSimpleConfigurationAdvancedConfiguration() throws Exception {
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        assertEquals(86400, samlSecurityRealm.getMaximumAuthenticationLifetime().longValue());
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertEquals(true, samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        assertEquals("/home/jdk/keystore", samlSecurityRealm.getEncryptionData().getKeystorePath());
        assertEquals(Secret.fromString("changeit"), samlSecurityRealm.getEncryptionData().getKeystorePassword());
        assertEquals(Secret.fromString("changeit"), samlSecurityRealm.getEncryptionData().getPrivateKeyPassword());
        assertEquals(true, samlSecurityRealm.getAdvancedConfiguration().getForceAuthn());
        assertEquals("anotherContext", samlSecurityRealm.getAdvancedConfiguration().getAuthnContextClassRef());
        assertEquals("spEntityId", samlSecurityRealm.getAdvancedConfiguration().getSpEntityId());
        assertEquals(SAML2_REDIRECT_BINDING_URI, samlSecurityRealm.getBinding());
    }

    @LocalData("testHugeNumberOfUsers")
    @WithTimeout(240)
    @Test
    public void testLoadGroupByGroupname() {
        assertEquals(samlSecurityRealm.loadGroupByGroupname("role500", true).getName(), "role500");
    }

    @LocalData("testHugeNumberOfUsers")
    @WithTimeout(240)
    @Test
    public void testLoadUserByUsername() {
        assertEquals(samlSecurityRealm.loadUserByUsername2("tesla").getUsername(), "tesla");
    }

    @LocalData("testReadSimpleConfiguration")
    @Test
    public void testGetters() throws IOException {
        SamlPluginConfig samlPluginConfig = new SamlPluginConfig(samlSecurityRealm.getDisplayNameAttributeName(),
                samlSecurityRealm.getGroupsAttributeName(),
                samlSecurityRealm.getMaximumAuthenticationLifetime(),
                samlSecurityRealm.getEmailAttributeName(),
                samlSecurityRealm.getIdpMetadataConfiguration(),
                samlSecurityRealm.getUsernameCaseConversion(),
                samlSecurityRealm.getUsernameAttributeName(),
                samlSecurityRealm.getLogoutUrl(),
                samlSecurityRealm.getBinding(),
                samlSecurityRealm.getEncryptionData(),
                samlSecurityRealm.getAdvancedConfiguration());
        assertEquals(samlPluginConfig.toString().equals(samlSecurityRealm.getSamlPluginConfig().toString()), true);

        assertEquals(new SamlAdvancedConfiguration(null,null,null, null, null).toString().contains("SamlAdvancedConfiguration"),true);
        assertEquals(new SamlAdvancedConfiguration(true,null,null, null, null).toString().contains("SamlAdvancedConfiguration"),true);
        assertEquals(new SamlAdvancedConfiguration(true,"","", "", 1).toString().contains("SamlAdvancedConfiguration"),true);

        SamlGroupAuthority authority = new SamlGroupAuthority("role001");
        assertEquals(authority.toString().equals("role001"),true);

        SamlUserDetails userDetails = new SamlUserDetails("tesla",new GrantedAuthority[]{authority});
        assertEquals(userDetails.toString().contains("tesla") && userDetails.toString().contains("role001"), true);

        assertThat(new SamlEncryptionData(null,null,null, null, false, false).toString(), containsString(
                "SamlEncryptionData"));
        assertThat(new SamlEncryptionData("", Secret.fromString(""), Secret.fromString(""), "", false, false).toString(), containsString("SamlEncryptionData"));

        assertEquals(new SamlFileResource("fileNotExists").exists(),false);
        SamlFileResource file = new SamlFileResource("fileWillExists","data");
        assertEquals(file.exists(),true);
        assertEquals(IOUtils.toByteArray(file.getInputStream()).length>0,true);
        IOUtils.write("data1",file.getOutputStream());
        assertEquals(IOUtils.toByteArray(file.getInputStream()).length>0,true);
        file.getFile().delete();
    }

    @LocalData
    @Test
    public void samlProfileWithEmptyGroups() {
        logs.capture(1);
        SAML2Profile samlProfile = new SAML2Profile();
        ArrayList<String> samlGroups = new ArrayList<>();
        samlGroups.add("group-1");
        samlGroups.add("");
        samlGroups.add("");
        samlGroups.add("");
        samlGroups.add("group-5");
        samlProfile.addAttribute(samlSecurityRealm.getGroupsAttributeName(), samlGroups);
        samlProfile.addAttribute(samlSecurityRealm.getUsernameAttributeName(), "user123");
        List<GrantedAuthority> grantedAuthorities = samlSecurityRealm.loadGrantedAuthorities(samlProfile);
        assertThat(grantedAuthorities, not(hasItem(blankGrantedAuthority())));
        List<LogRecord> records = logs.getRecords();
        assertThat(records, hasSize(1));
        assertThat(records.get(0).getMessage(), allOf(containsString("Found 3 empty groups"), containsString("user123")));
    }

    @Test
    @LocalData // config.xml from saml-plugin 0.14
    public void upgradeIDPMetadataFileTest() throws IOException {
        // after upgrading a new file should be automatically created under JENKINS_HOME
        // without user interaction

        String idpMetadata = FileUtils.readFileToString(new File(SamlSecurityRealm.getIDPMetadataFilePath()));
        String configuredMetadata = ((SamlSecurityRealm) jenkinsRule.getInstance().getSecurityRealm())
                .getIdpMetadataConfiguration().getIdpMetadata();
        idpMetadata = idpMetadata.replace(" ", ""); // remove spaces
        idpMetadata = idpMetadata.replace("\\n", ""); // remove new lines
        configuredMetadata = configuredMetadata.replace(" ", ""); // remove spaces
        configuredMetadata = configuredMetadata.replace("\\n", ""); // remove new lines
        assertThat(idpMetadata, equalTo(configuredMetadata));
    }

    private static BlankGrantedAuthorityTypeSafeMatcher blankGrantedAuthority() {
        return new BlankGrantedAuthorityTypeSafeMatcher();
    }

    private static class BlankGrantedAuthorityTypeSafeMatcher extends TypeSafeMatcher<GrantedAuthority> {
        @Override
        public void describeTo(Description description) {
            description.appendText("a blank authority");
        }

        @Override
        protected boolean matchesSafely(GrantedAuthority item) {
            return StringUtils.isBlank(item.getAuthority());
        }
    }
}
