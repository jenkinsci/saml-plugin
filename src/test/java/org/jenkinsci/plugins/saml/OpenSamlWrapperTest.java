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
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.mockito.Mockito;
import org.pac4j.saml.profile.SAML2Profile;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;

/**
 * Different OpenSAMLWrapper classes tests
 */
public class OpenSamlWrapperTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void metadataWrapper() throws IOException, ServletException {
        String metadata = IOUtils.toString(this.getClass().getClassLoader().getResourceAsStream("org/jenkinsci/plugins/saml/OpenSamlWrapperTest/metadataWrapper/metadata.xml"));
        SamlSecurityRealm samlSecurity = new SamlSecurityRealm(new IdpMetadataConfiguration(metadata),
                "displayName", "groups", 10000,
                "uid", "email", "/logout", null,
                null, "none",SAML2_REDIRECT_BINDING_URI,
                java.util.Collections.emptyList());
        jenkinsRule.jenkins.setSecurityRealm(samlSecurity);
        SamlSPMetadataWrapper samlSPMetadataWrapper = new SamlSPMetadataWrapper(samlSecurity.getSamlPluginConfig(), null, null);
        HttpResponse process = samlSPMetadataWrapper.get();
        StaplerResponse mockResponse = Mockito.mock(StaplerResponse.class);
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
    public void metadataWrapperWitEncrytionConfigured() throws IOException, ServletException {
        String metadata = IOUtils.toString(this.getClass().getClassLoader().getResourceAsStream("org/jenkinsci/plugins/saml/OpenSamlWrapperTest/metadataWrapper/metadata.xml"));
        BundleKeyStore ks = new BundleKeyStore();
        SamlEncryptionData encryptionData = new SamlEncryptionData(ks.getKeystorePath(),
                Secret.fromString(ks.getKsPassword()), Secret.fromString(ks.getKsPkPassword()), ks.getKsPkAlias(), true);
        SamlSecurityRealm samlSecurity = new SamlSecurityRealm(new IdpMetadataConfiguration(metadata),
                "displayName", "groups", 10000,
                "uid", "email", "/logout", null,
                encryptionData, "none",SAML2_REDIRECT_BINDING_URI,
                java.util.Collections.emptyList());
        jenkinsRule.jenkins.setSecurityRealm(samlSecurity);
        SamlSPMetadataWrapper samlSPMetadataWrapper = new SamlSPMetadataWrapper(samlSecurity.getSamlPluginConfig(), null, null);
        HttpResponse process = samlSPMetadataWrapper.get();
        StaplerResponse mockResponse = Mockito.mock(StaplerResponse.class);
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

    //TODO [kuisathaverat] incomplete
    public void profileWrapper() throws Exception {
        String metadata = IOUtils.toString(this.getClass().getClassLoader().getResourceAsStream("org/jenkinsci/plugins/saml/OpenSamlWrapperTest/metadataWrapper/metadata.xml"));
        String samlResponse = IOUtils.toString(this.getClass().getClassLoader().getResourceAsStream("org/jenkinsci/plugins/saml/OpenSamlWrapperTest/profileWrapper/samlresponse.xml"));

        SamlSecurityRealm samlSecurity = new SamlSecurityRealm(new IdpMetadataConfiguration(metadata),
                "displayName", "groups", 10000,
                "uid", "email", "/logout", null,
                null, "none", SAML2_REDIRECT_BINDING_URI,
                java.util.Collections.emptyList());
        jenkinsRule.jenkins.setSecurityRealm(samlSecurity);

        DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
        samlResponse = samlResponse.replace("DATE_NOW",df.format(new Date()));
        samlResponse = samlResponse.replace("DATE_AFTER",df.format(new Date(System.currentTimeMillis() + 1000000)));
        samlResponse = samlResponse.replace("CONSUMER_SERVICE",samlSecurity.getSamlPluginConfig().getConsumerServiceUrl());
        samlResponse = samlResponse.replace("ENTITY_ID","http://192.168.99.100:8080/simplesaml/saml2/idp/metadata.php");

        StaplerResponse mockResponse = Mockito.mock(StaplerResponse.class);
        StaplerRequest mockRequest = Mockito.mock(StaplerRequest.class);
        when(mockRequest.getMethod()).thenReturn("POST");
        when(mockRequest.getParameter("SAMLResponse")).thenReturn(java.util.Base64.getEncoder().encodeToString(samlResponse.getBytes("UTF-8")));

        SamlProfileWrapper samlProfileWrapper = new SamlProfileWrapper(samlSecurity.getSamlPluginConfig(), mockRequest, mockResponse);
        SAML2Profile process = samlProfileWrapper.get();

    }
}
