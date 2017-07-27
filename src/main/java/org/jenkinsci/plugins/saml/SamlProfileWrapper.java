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

import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.profile.SAML2Profile;

import java.util.logging.Logger;

/**
 * Process to response from the IdP to obtain the SAML2Profile of the user.
 */
public class SamlProfileWrapper extends OpenSAMLWrapper<SAML2Profile> {
    private static final Logger LOG = Logger.getLogger(SamlProfileWrapper.class.getName());


    public SamlProfileWrapper(SamlPluginConfig samlPluginConfig, StaplerRequest request, StaplerResponse response) {
        this.request = request;
        this.response = response;
        this.samlPluginConfig = samlPluginConfig;
    }

    /**
     * @return the SAML2Profile of the user returned by the IdP.
     */
    @Override
    SAML2Profile process() {
        SAML2Credentials credentials;
        SAML2Profile saml2Profile;
        try {
            final SAML2Client client = createSAML2Client();
            final WebContext context = createWebContext();
            credentials = client.getCredentials(context);
            saml2Profile = client.getUserProfile(credentials, context);
        } catch (HttpAction e) {
            throw new IllegalStateException(e);
        }

        if (saml2Profile == null) {
            String msg = "Could not find user profile for SAML credentials: " + credentials;
            LOG.severe(msg);
            throw new IllegalStateException(msg);
        }

        LOG.finer(saml2Profile.toString());
        return saml2Profile;
    }
}
