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

import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerResponse;
import org.mockito.Mockito;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.hamcrest.core.StringContains.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

/**
 * Different OpenSAMLWrapper classes tests
 */
public class OpenSamlWrapperTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Test
    public void metadataWrapper() throws IOException, ServletException {
        String metadata = IOUtils.toString(this.getClass().getClassLoader().getResourceAsStream("org/jenkinsci/plugins/saml/SamlSecurityRealmTest/metadataWrapper/metadata.xml"));
        SamlSecurityRealm samlSecurity = new SamlSecurityRealm(metadata, "displayName", "groups", 10000, "uid", "email", "/logout", null, null, null);
        jenkinsRule.jenkins.setSecurityRealm(samlSecurity);
        SamlSPMetadataWrapper samlSPMetadataWrapper = new SamlSPMetadataWrapper(samlSecurity.getSamlPluginConfig(), null, null);
        HttpResponse process = samlSPMetadataWrapper.process();
        StaplerResponse mockResponse = Mockito.mock(StaplerResponse.class);
        StringWriter stringWriter = new StringWriter();
        when(mockResponse.getWriter()).thenReturn(new PrintWriter(stringWriter));
        process.generateResponse(null, mockResponse, null);
        String result = stringWriter.toString();
        // Some random checks as the full XML comparison fails because of reformatting on processing
        assertThat(result, containsString("EntityDescriptor"));
        assertThat(result, containsString("<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"));
        assertThat(result, containsString("<ds:X509Certificate>"));
    }
}
