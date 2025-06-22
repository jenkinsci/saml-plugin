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

import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.saml.client.SAML2Client;

/**
 * Process the current configuration and request to prepare a Redirection to the IdP.
 */
public class SamlRedirectActionWrapper extends OpenSAMLWrapper<RedirectionAction> {

    public SamlRedirectActionWrapper(
            SamlPluginConfig samlPluginConfig, StaplerRequest2 request, StaplerResponse2 response) {
        this.request = request;
        this.response = response;
        this.samlPluginConfig = samlPluginConfig;
    }

    /**
     * @return the redirection URL to the IdP.
     * @throws IllegalStateException if something goes wrong.
     */
    @Override
    protected RedirectionAction process() throws IllegalStateException {
        try (SAML2Client client = createSAML2Client()) {
            WebContext context = createWebContext();
            SessionStore sessionStore = createSessionStore();
            CallContext ctx = new CallContext(context, sessionStore);
            RedirectionAction redirection = client.getRedirectionAction(ctx).orElse(null);
            client.destroy();
            return redirection;
        } catch (HttpAction e) {
            throw new IllegalStateException(e);
        }
    }
}
