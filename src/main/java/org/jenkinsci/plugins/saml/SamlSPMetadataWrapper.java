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

import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.pac4j.saml.client.SAML2Client;

/**
 * build the Service Provider(SP) metadata from the configuration.
 */
public class SamlSPMetadataWrapper extends OpenSAMLWrapper<HttpResponse> {

    public SamlSPMetadataWrapper(SamlPluginConfig samlPluginConfig, StaplerRequest request, StaplerResponse response) {
        this.request = request;
        this.response = response;
        this.samlPluginConfig = samlPluginConfig;
    }

    /**
     * @return the metadata of the SP.
     * @throws IllegalStateException if something goes wrong.
     */
    @Override
    protected HttpResponse process() throws IllegalStateException {
        final SAML2Client client = createSAML2Client();
        return HttpResponses.plainText(client.getServiceProviderMetadataResolver().getMetadata());
    }
}
