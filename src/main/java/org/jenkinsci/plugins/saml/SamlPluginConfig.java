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

import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

/**
 * contains all the Jenkins SAML Plugin settings
 */
public class SamlPluginConfig {
    private final String displayNameAttributeName;
    private final String groupsAttributeName;
    private final int maximumAuthenticationLifetime;
    private final String emailAttributeName;

    private final IdpMetadataConfiguration idpMetadataConfiguration;
    private final String usernameCaseConversion;
    private final String usernameAttributeName;
    private final String logoutUrl;
    private final String binding;

    private final SamlEncryptionData encryptionData;
    private final SamlAdvancedConfiguration advancedConfiguration;

    public SamlPluginConfig(
            String displayNameAttributeName,
            String groupsAttributeName,
            int maximumAuthenticationLifetime,
            String emailAttributeName,
            IdpMetadataConfiguration idpMetadataConfiguration,
            String usernameCaseConversion,
            String usernameAttributeName,
            String logoutUrl,
            String binding,
            SamlEncryptionData encryptionData,
            SamlAdvancedConfiguration advancedConfiguration) {
        this.displayNameAttributeName = displayNameAttributeName;
        this.groupsAttributeName = groupsAttributeName;
        this.maximumAuthenticationLifetime = maximumAuthenticationLifetime;
        this.emailAttributeName = emailAttributeName;
        this.idpMetadataConfiguration = idpMetadataConfiguration;
        this.usernameCaseConversion =
                StringUtils.defaultIfBlank(usernameCaseConversion, DEFAULT_USERNAME_CASE_CONVERSION);
        this.usernameAttributeName = hudson.Util.fixEmptyAndTrim(usernameAttributeName);
        this.logoutUrl = logoutUrl;
        this.binding = binding;
        this.encryptionData = encryptionData;
        this.advancedConfiguration = advancedConfiguration;
    }

    public String getUsernameAttributeName() {
        return usernameAttributeName;
    }

    public String getDisplayNameAttributeName() {
        return displayNameAttributeName;
    }

    public String getGroupsAttributeName() {
        return groupsAttributeName;
    }

    public Integer getMaximumAuthenticationLifetime() {
        return maximumAuthenticationLifetime;
    }

    public SamlAdvancedConfiguration getAdvancedConfiguration() {
        return advancedConfiguration;
    }

    public Boolean getForceAuthn() {
        return getAdvancedConfiguration() != null ? getAdvancedConfiguration().getForceAuthn() : Boolean.FALSE;
    }

    public String getAuthnContextClassRef() {
        return getAdvancedConfiguration() != null ? getAdvancedConfiguration().getAuthnContextClassRef() : null;
    }

    public String getSpEntityId() {
        return getAdvancedConfiguration() != null ? getAdvancedConfiguration().getSpEntityId() : null;
    }

    public String getNameIdPolicyFormat() {
        return getAdvancedConfiguration() != null ? getAdvancedConfiguration().getNameIdPolicyFormat() : null;
    }

    public SamlEncryptionData getEncryptionData() {
        return encryptionData;
    }

    public String getUsernameCaseConversion() {
        return usernameCaseConversion;
    }

    public String getEmailAttributeName() {
        return emailAttributeName;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public String getConsumerServiceUrl() {
        return baseUrl() + CONSUMER_SERVICE_URL_PATH;
    }

    public String baseUrl() {
        return Jenkins.get().getRootUrl();
    }

    public IdpMetadataConfiguration getIdpMetadataConfiguration() {
        return idpMetadataConfiguration;
    }

    public String getBinding() {
        return binding;
    }

    @Override
    public String toString() {
        return "SamlPluginConfig{" + "idpMetadataConfiguration='" + getIdpMetadataConfiguration() + '\''
                + ", displayNameAttributeName='" + getDisplayNameAttributeName() + '\'' + ", groupsAttributeName='"
                + getGroupsAttributeName() + '\'' + ", emailAttributeName='" + getEmailAttributeName() + '\''
                + ", usernameAttributeName='" + getUsernameAttributeName() + '\''
                + ", maximumAuthenticationLifetime=" + getMaximumAuthenticationLifetime()
                + ", usernameCaseConversion='" + getUsernameCaseConversion() + '\'' + ", logoutUrl='"
                + getLogoutUrl() + '\'' + ", binding='" + getBinding() + '\'' + ", encryptionData="
                + getEncryptionData() + ", advancedConfiguration=" + getAdvancedConfiguration() + '}';
    }
}
