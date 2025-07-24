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

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.CONSUMER_SERVICE_URL_PATH;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.DEFAULT_USERNAME_CASE_CONVERSION;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.List;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

/**
 * contains all the Jenkins SAML Plugin settings
 */
public record SamlPluginConfig(
        String displayNameAttributeName,
        String groupsAttributeName,
        String emailAttributeName,
        IdpMetadataConfiguration idpMetadataConfiguration,
        String usernameCaseConversion,
        String usernameAttributeName,
        String logoutUrl,
        @NonNull List<SamlProperty> properties) {
    public SamlPluginConfig(
            String displayNameAttributeName,
            String groupsAttributeName,
            String emailAttributeName,
            IdpMetadataConfiguration idpMetadataConfiguration,
            String usernameCaseConversion,
            String usernameAttributeName,
            String logoutUrl,
            @NonNull List<SamlProperty> properties) {
        this.displayNameAttributeName = displayNameAttributeName;
        this.groupsAttributeName = groupsAttributeName;
        this.emailAttributeName = emailAttributeName;
        this.idpMetadataConfiguration = idpMetadataConfiguration;
        this.usernameCaseConversion =
                StringUtils.defaultIfBlank(usernameCaseConversion, DEFAULT_USERNAME_CASE_CONVERSION);
        this.usernameAttributeName = hudson.Util.fixEmptyAndTrim(usernameAttributeName);
        this.logoutUrl = logoutUrl;
        this.properties = List.copyOf(properties);
    }

    public String getConsumerServiceUrl() {
        return baseUrl() + CONSUMER_SERVICE_URL_PATH;
    }

    public String baseUrl() {
        return Jenkins.get().getRootUrl();
    }

    @Override
    @NonNull
    public String toString() {
        return "SamlPluginConfig{" + "idpMetadataConfiguration='" + idpMetadataConfiguration() + '\''
                + ", displayNameAttributeName='" + displayNameAttributeName() + '\'' + ", groupsAttributeName='"
                + groupsAttributeName() + '\'' + ", emailAttributeName='" + emailAttributeName() + '\''
                + ", usernameAttributeName='" + usernameAttributeName() + '\''
                + ", usernameCaseConversion='" + usernameCaseConversion() + '\'' + ", logoutUrl='"
                + logoutUrl() + '\'' + ",properties=" + properties() + '}';
    }
}
