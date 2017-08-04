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

import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.CONSUMER_SERVICE_URL_PATH;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.DEFAULT_USERNAME_CASE_CONVERSION;

/**
 * contains all the Jenkins SAML Plugin settings
 */
public class SamlPluginConfig {
    private String displayNameAttributeName;
    private String groupsAttributeName;
    private int maximumAuthenticationLifetime;
    private String emailAttributeName;

    private final String idpMetadata;
    private final String usernameCaseConversion;
    private final String usernameAttributeName;
    private final String logoutUrl;

    private SamlEncryptionData encryptionData;
    private SamlAdvancedConfiguration advancedConfiguration;

    public SamlPluginConfig(String displayNameAttributeName, String groupsAttributeName,
                            int maximumAuthenticationLifetime, String emailAttributeName, String idpMetadata,
                            String usernameCaseConversion, String usernameAttributeName, String logoutUrl,
                            SamlEncryptionData encryptionData, SamlAdvancedConfiguration advancedConfiguration) {
        this.displayNameAttributeName = displayNameAttributeName;
        this.groupsAttributeName = groupsAttributeName;
        this.maximumAuthenticationLifetime = maximumAuthenticationLifetime;
        this.emailAttributeName = emailAttributeName;
        this.idpMetadata = hudson.Util.fixEmptyAndTrim(idpMetadata);
        this.usernameCaseConversion = StringUtils.defaultIfBlank(usernameCaseConversion, DEFAULT_USERNAME_CASE_CONVERSION);
        this.usernameAttributeName = hudson.Util.fixEmptyAndTrim(usernameAttributeName);
        this.logoutUrl = logoutUrl;
        this.encryptionData = encryptionData;
        this.advancedConfiguration = advancedConfiguration;
    }

    public String getIdpMetadata() {
        return idpMetadata;
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
        return Jenkins.getInstance().getRootUrl();
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SamlPluginConfig{");
        sb.append("idpMetadata='").append(getIdpMetadata()).append('\'');
        sb.append(", displayNameAttributeName='").append(getDisplayNameAttributeName()).append('\'');
        sb.append(", groupsAttributeName='").append(getGroupsAttributeName()).append('\'');
        sb.append(", emailAttributeName='").append(getEmailAttributeName()).append('\'');
        sb.append(", usernameAttributeName='").append(getUsernameAttributeName()).append('\'');
        sb.append(", maximumAuthenticationLifetime=").append(getMaximumAuthenticationLifetime());
        sb.append(", usernameCaseConversion='").append(getUsernameCaseConversion()).append('\'');
        sb.append(", logoutUrl='").append(getLogoutUrl()).append('\'');
        sb.append(", encryptionData=").append(getEncryptionData());
        sb.append(", advancedConfiguration=").append(getAdvancedConfiguration());
        sb.append('}');
        return sb.toString();
    }
}
