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

import hudson.util.Secret;
import jakarta.servlet.ServletException;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerResponse2;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.mockito.Mockito.when;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;

/**
 * Different OpenSAMLWrapper classes tests
 */
@WithJenkins
class OpenSamlWrapperTest {

    @Test
    void metadataWrapper(JenkinsRule jenkinsRule) throws IOException, ServletException {
        String metadata = IOUtils.toString(
                Objects.requireNonNull(this.getClass().getClassLoader().getResourceAsStream(
                        "org/jenkinsci" + "/plugins/saml" + "/OpenSamlWrapperTest/metadataWrapper/metadata.xml")),
                StandardCharsets.UTF_8);
        SamlSecurityRealm samlSecurity = new SamlSecurityRealm(new IdpMetadataConfiguration(metadata),
                "displayName", "groups", 10000,
                "uid", "email", "/logout", null,
                null, "none", SAML2_REDIRECT_BINDING_URI,
                java.util.Collections.emptyList());
        jenkinsRule.jenkins.setSecurityRealm(samlSecurity);
        SamlSPMetadataWrapper samlSPMetadataWrapper = new SamlSPMetadataWrapper(samlSecurity.getSamlPluginConfig(), null, null);
        HttpResponse process = samlSPMetadataWrapper.get();
        StaplerResponse2 mockResponse = Mockito.mock(StaplerResponse2.class);
        StringWriter stringWriter = new StringWriter();
        when(mockResponse.getWriter()).thenReturn(new PrintWriter(stringWriter));
        process.generateResponse(null, mockResponse, null);
        String result = stringWriter.toString();
        // Some random checks as the full XML comparison fails because of reformatting on processing
        assertThat(result, containsString("EntityDescriptor"));
        assertThat(result, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"));
        assertThat(result, containsString("<md:SPSSODescriptor"));
    }

    @Test
    void metadataWrapperWithEncryptionConfigured(JenkinsRule jenkinsRule) throws IOException, ServletException {
        String metadata = IOUtils.toString(
                Objects.requireNonNull(this.getClass().getClassLoader().getResourceAsStream(
                        "org/jenkinsci" + "/plugins/saml/" + "OpenSamlWrapperTest/metadataWrapper/metadata.xml")),
                StandardCharsets.UTF_8);
        BundleKeyStore ks = new BundleKeyStore();
        SamlEncryptionData encryptionData = new SamlEncryptionData(ks.getKeystorePath(),
                Secret.fromString(ks.getKsPassword()), Secret.fromString(ks.getKsPkPassword()), ks.getKsPkAlias(),
                true, true);
        SamlSecurityRealm samlSecurity = new SamlSecurityRealm(new IdpMetadataConfiguration(metadata),
                "displayName", "groups", 10000,
                "uid", "email", "/logout", null,
                encryptionData, "none", SAML2_REDIRECT_BINDING_URI,
                java.util.Collections.emptyList());
        jenkinsRule.jenkins.setSecurityRealm(samlSecurity);
        SamlSPMetadataWrapper samlSPMetadataWrapper = new SamlSPMetadataWrapper(samlSecurity.getSamlPluginConfig(), null, null);
        HttpResponse process = samlSPMetadataWrapper.get();
        StaplerResponse2 mockResponse = Mockito.mock(StaplerResponse2.class);
        StringWriter stringWriter = new StringWriter();
        when(mockResponse.getWriter()).thenReturn(new PrintWriter(stringWriter));
        process.generateResponse(null, mockResponse, null);
        String result = stringWriter.toString();
        // Some random checks as the full XML comparison fails because of reformatting on processing
        assertThat(result, containsString("EntityDescriptor"));
        assertThat(result, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"));
        assertThat(result, containsString("<md:SPSSODescriptor"));
        assertThat(result, containsString("<ds:X509Certificate>"));
    }
}
