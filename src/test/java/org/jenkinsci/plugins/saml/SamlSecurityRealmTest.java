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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.IsIterableContaining.hasItem;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_POST_BINDING_URI;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.XmlFile;
import hudson.model.Descriptor;
import hudson.security.AuthorizationStrategy;
import hudson.security.SecurityRealm;
import hudson.util.Secret;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.jenkinsci.plugins.saml.properties.DataBindingMethod;
import org.jenkinsci.plugins.saml.properties.ForceAuthentication;
import org.jenkinsci.plugins.saml.properties.MaximumAuthenticationLifetime;
import org.jenkinsci.plugins.saml.properties.SpEntityId;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.TestExtension;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import org.jvnet.hudson.test.recipes.WithTimeout;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.saml.profile.SAML2Profile;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Different configurations tests
 */
@WithJenkins
class SamlSecurityRealmTest {

    private JenkinsRule r;

    public final LogRecorder logs = new LogRecorder().record(SamlSecurityRealm.class, Level.WARNING);

    private SamlSecurityRealm samlSecurityRealm;

    @BeforeEach
    void start(JenkinsRule jenkinsRule) {
        this.r = jenkinsRule;
    }

    private void expectSamlSecurityRealm() {
        SecurityRealm securityRealm = r.getInstance().getSecurityRealm();
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
    void testReadSimpleConfiguration() throws IOException {
        expectSamlSecurityRealm();
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        ensurePropertyMissing(MaximumAuthenticationLifetime.class);
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:mail", samlSecurityRealm.getEmailAttributeName());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertTrue(
                samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        ensurePropertyMissing(DataBindingMethod.class);
    }

    @NonNull
    private <T extends SamlProperty> T ensureProperty(@NonNull Class<T> cls) {
        return ensureProperty(samlSecurityRealm, cls);
    }

    @NonNull
    public static <T extends SamlProperty> T ensureProperty(
            @NonNull SamlSecurityRealm samlSecurityRealm, @NonNull Class<T> cls) {
        var first = samlSecurityRealm.getProperties().stream()
                .filter(cls::isInstance)
                .map(cls::cast)
                .findFirst();
        assertTrue(first.isPresent(), cls.getSimpleName() + " property should be present");
        return first.get();
    }

    private <T extends SamlProperty> @NonNull boolean ensurePropertyMissing(@NonNull Class<T> cls) {
        return ensurePropertyMissing(samlSecurityRealm, cls);
    }

    public static <T extends SamlProperty> boolean ensurePropertyMissing(
            @NonNull SamlSecurityRealm samlSecurityRealm, @NonNull Class<T> cls) {
        return samlSecurityRealm.getProperties().stream().noneMatch(cls::isInstance);
    }

    @LocalData
    @Test
    void testReadSimpleConfigurationHTTPPost() throws IOException {
        expectSamlSecurityRealm();
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        ensurePropertyMissing(MaximumAuthenticationLifetime.class);
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:mail", samlSecurityRealm.getEmailAttributeName());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertTrue(
                samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        assertThat(ensureProperty(DataBindingMethod.class).getValue(), equalTo(SAML2_POST_BINDING_URI));
    }

    @LocalData
    @Test
    void testReadSimpleConfigurationLowercase() throws Exception {
        expectSamlSecurityRealm();
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        ensurePropertyMissing(MaximumAuthenticationLifetime.class);
        assertEquals("lowercase", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertTrue(
                samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        ensurePropertyMissing(DataBindingMethod.class);
    }

    @LocalData
    @Test
    void testReadSimpleConfigurationUppercase() throws Exception {
        expectSamlSecurityRealm();
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        ensurePropertyMissing(MaximumAuthenticationLifetime.class);
        assertEquals("uppercase", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertTrue(
                samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        ensurePropertyMissing(DataBindingMethod.class);
    }

    @Issue("JENKINS-46007")
    @LocalData
    @Test
    void testReadSimpleConfigurationEncryptionData() throws Exception {
        expectSamlSecurityRealm();
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        ensurePropertyMissing(MaximumAuthenticationLifetime.class);
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertTrue(
                samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        var samlEncryptionData = ensureProperty(SamlEncryptionData.class);
        assertEquals("/home/jdk/keystore", samlEncryptionData.getKeystorePath());
        assertEquals(Secret.fromString("changeitks"), samlEncryptionData.getKeystorePassword());
        assertEquals(Secret.fromString("changeitpk"), samlEncryptionData.getPrivateKeyPassword());
        ensurePropertyMissing(DataBindingMethod.class);
        r.jenkins.setAuthorizationStrategy(
                AuthorizationStrategy.UNSECURED); // since we cannot actually log in during the test
        r.submit(r.createWebClient().goTo("configureSecurity").getFormByName("config"));
        samlSecurityRealm = (SamlSecurityRealm) r.jenkins.getSecurityRealm();
        assertEquals(Secret.fromString("changeitks"), samlEncryptionData.getKeystorePassword());
        assertEquals(Secret.fromString("changeitpk"), samlEncryptionData.getPrivateKeyPassword());
        assertThat(new XmlFile(new File(r.jenkins.root, "config.xml")).asString(), not(containsString("changeit")));
        assertFalse(samlEncryptionData.isForceSignRedirectBindingAuthnRequest());
    }

    @LocalData
    @Test
    void testReadSimpleConfigurationAdvancedConfiguration() throws Exception {
        expectSamlSecurityRealm();
        assertEquals("urn:mace:dir:attribute-def:displayName", samlSecurityRealm.getDisplayNameAttributeName());
        assertEquals("urn:mace:dir:attribute-def:groups", samlSecurityRealm.getGroupsAttributeName());
        ensurePropertyMissing(MaximumAuthenticationLifetime.class);
        assertEquals("none", samlSecurityRealm.getUsernameCaseConversion());
        assertEquals("urn:mace:dir:attribute-def:uid", samlSecurityRealm.getUsernameAttributeName());
        assertTrue(
                samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata().startsWith("<?xml version"));
        var samlEncryptionData = ensureProperty(SamlEncryptionData.class);
        assertEquals("/home/jdk/keystore", samlEncryptionData.getKeystorePath());
        assertEquals(Secret.fromString("changeitks"), samlEncryptionData.getKeystorePassword());
        assertEquals(Secret.fromString("changeitpk"), samlEncryptionData.getPrivateKeyPassword());
        ensureProperty(ForceAuthentication.class);
        assertThat(ensureProperty(SpEntityId.class).getValue(), equalTo("spEntityId"));
        ensurePropertyMissing(DataBindingMethod.class);
    }

    @LocalData("testHugeNumberOfUsers")
    @WithTimeout(240)
    @Test
    void testLoadGroupByGroupname() {
        expectSamlSecurityRealm();
        assertEquals(
                "role500",
                samlSecurityRealm.loadGroupByGroupname("role500", true).getName());
    }

    @LocalData("testHugeNumberOfUsers")
    @WithTimeout(240)
    @Test
    void testLoadUserByUsername() {
        expectSamlSecurityRealm();
        assertEquals("tesla", samlSecurityRealm.loadUserByUsername2("tesla").getUsername());
    }

    @LocalData("testReadSimpleConfiguration")
    @Test
    void testGetters() throws IOException {
        expectSamlSecurityRealm();
        SamlPluginConfig samlPluginConfig = new SamlPluginConfig(
                samlSecurityRealm.getDisplayNameAttributeName(),
                samlSecurityRealm.getGroupsAttributeName(),
                samlSecurityRealm.getEmailAttributeName(),
                samlSecurityRealm.getIdpMetadataConfiguration(),
                samlSecurityRealm.getUsernameCaseConversion(),
                samlSecurityRealm.getUsernameAttributeName(),
                samlSecurityRealm.getLogoutUrl(),
                samlSecurityRealm.getProperties());
        assertEquals(
                samlPluginConfig.toString(),
                samlSecurityRealm.getSamlPluginConfig().toString());
        SimpleGrantedAuthority authority = new SimpleGrantedAuthority("role001");
        assertEquals("role001", authority.toString());

        SamlUserDetails userDetails = new SamlUserDetails("tesla", Collections.singletonList(authority));
        assertTrue(userDetails.toString().contains("tesla")
                && userDetails.toString().contains("role001"));

        assertThat(
                new SamlEncryptionData(null, null, null, null, false, false).toString(),
                containsString("SamlEncryptionData"));
        assertThat(
                new SamlEncryptionData("", Secret.fromString(""), Secret.fromString(""), "", false, false).toString(),
                containsString("SamlEncryptionData"));

        assertFalse(SamlFileResourceFactory.create("fileNotExists", false).exists());
        var file = SamlFileResourceFactory.create("fileWillExists", "data", false);
        assertTrue(file.exists());
        assertTrue(IOUtils.toByteArray(file.getInputStream()).length > 0);
        IOUtils.write("data1", file.getOutputStream(), StandardCharsets.UTF_8);
        assertTrue(IOUtils.toByteArray(file.getInputStream()).length > 0);
        //noinspection ResultOfMethodCallIgnored
        file.getFile().delete();
    }

    @LocalData
    @Test
    void samlProfileWithEmptyGroups() {
        expectSamlSecurityRealm();
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
        assertThat(
                records.get(0).getMessage(), allOf(containsString("Found 3 empty groups"), containsString("user123")));
    }

    // config.xml from saml-plugin 0.14
    @Test
    @LocalData
    void upgradeIDPMetadataFileTest() throws IOException {
        expectSamlSecurityRealm();
        // after upgrading a new file should be automatically created under JENKINS_HOME
        // without user interaction

        String idpMetadata = FileUtils.readFileToString(
                new File(SamlSecurityRealm.getIDPMetadataFilePath()), StandardCharsets.UTF_8);
        String configuredMetadata =
                samlSecurityRealm.getIdpMetadataConfiguration().getIdpMetadata();
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

    @Test
    void ensurePropertiesCompatibility() throws Descriptor.FormException, IOException {
        samlSecurityRealm = new SamlSecurityRealm(
                new IdpMetadataConfiguration("""
                <?xml version="1.0">
                """),
                "urn:mace:dir:attribute-def:displayName",
                "urn:mace:dir:attribute-def:groups",
                "urn:mace:dir:attribute-def:mail",
                "urn:mace:dir:attribute-def:uid",
                "none",
                null,
                null);
        // Each property can be used alone
        samlSecurityRealm.setProperties(List.of(new PropertyA()));
        samlSecurityRealm.setProperties(List.of(new PropertyB()));
        // But both can't be picked together because B declared A as incompatible
        assertThrowsExactly(
                Descriptor.FormException.class,
                () -> samlSecurityRealm.setProperties(List.of(new PropertyA(), new PropertyB())));
    }

    public static class PropertyA extends SamlProperty {
        @DataBoundConstructor
        public PropertyA() {}

        @Override
        public @NonNull SamlPropertyExecution newExecution() {
            return new ExecutionImpl();
        }

        @TestExtension
        public static class DescriptorImpl extends SamlPropertyDescriptor {
            @NonNull
            @Override
            public String getDisplayName() {
                return "Property A";
            }
        }

        private record ExecutionImpl() implements SamlPropertyExecution {}
    }

    public static class PropertyB extends SamlProperty {
        @DataBoundConstructor
        public PropertyB() {}

        @Override
        public @NonNull SamlPropertyExecution newExecution() {
            return new ExecutionImpl();
        }

        @TestExtension
        public static class DescriptorImpl extends SamlPropertyDescriptor {
            @NonNull
            @Override
            public String getDisplayName() {
                return "Property B";
            }

            @Override
            public @NotNull List<Class<? extends SamlProperty>> getIncompatibleProperties() {
                return List.of(PropertyA.class);
            }
        }

        private record ExecutionImpl() implements SamlPropertyExecution {}
    }
}
