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

import org.apache.commons.lang.StringUtils;
import org.pac4j.saml.config.SAML2Configuration;

import jenkins.model.Jenkins;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.CONSUMER_SERVICE_URL_PATH;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.DEFAULT_USERNAME_CASE_CONVERSION;

import java.util.Arrays;
import java.util.logging.Logger;

/**
 * contains all the Jenkins SAML Plugin settings
 */
public class SamlPluginConfig {
    private static final BundleKeyStore KS = new BundleKeyStore();
    private static final Logger LOG = Logger.getLogger(SamlPluginConfig.class.getName());

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

    public SamlPluginConfig(String displayNameAttributeName, String groupsAttributeName,
                            int maximumAuthenticationLifetime, String emailAttributeName, IdpMetadataConfiguration idpMetadataConfiguration,
                            String usernameCaseConversion, String usernameAttributeName, String logoutUrl, String binding,
                            SamlEncryptionData encryptionData, SamlAdvancedConfiguration advancedConfiguration) {
        this.displayNameAttributeName = displayNameAttributeName;
        this.groupsAttributeName = groupsAttributeName;
        this.maximumAuthenticationLifetime = maximumAuthenticationLifetime;
        this.emailAttributeName = emailAttributeName;
        this.idpMetadataConfiguration = idpMetadataConfiguration;
        this.usernameCaseConversion = StringUtils.defaultIfBlank(usernameCaseConversion, DEFAULT_USERNAME_CASE_CONVERSION);
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

    public SAML2Configuration getSAML2Configuration(){
        SAML2Configuration config = new SAML2Configuration();
        config.setIdentityProviderMetadataResource(new SamlFileResource(SamlSecurityRealm.getIDPMetadataFilePath()));
        config.setAuthnRequestBindingType(getBinding());

        SamlEncryptionData encryptionData = getEncryptionData();
        if (encryptionData != null) {
            config.setAuthnRequestSigned(encryptionData.isForceSignRedirectBindingAuthnRequest());
            config.setWantsAssertionsSigned(encryptionData.isWantsAssertionsSigned());
        } else {
            config.setAuthnRequestSigned(false);
            config.setWantsAssertionsSigned(false);
        }

        if(encryptionData != null && StringUtils.isNotBlank(encryptionData.getKeystorePath())){
            config.setKeystorePath(encryptionData.getKeystorePath());
            config.setKeystorePassword(encryptionData.getKeystorePasswordPlainText());
            config.setPrivateKeyPassword(encryptionData.getPrivateKeyPasswordPlainText());
            config.setKeyStoreAlias(encryptionData.getPrivateKeyAlias());
        } else {
            if (!KS.isValid()) {
                KS.init();
            }
            if (KS.isUsingDemoKeyStore()) {
                LOG.warning("Using bundled keystore : " + KS.getKeystorePath());
            }
            config.setKeystorePath(KS.getKeystorePath());
            config.setKeystorePassword(KS.getKsPassword());
            config.setPrivateKeyPassword(KS.getKsPkPassword());
            config.setKeyStoreAlias(KS.getKsPkAlias());
        }

        config.setMaximumAuthenticationLifetime(getMaximumAuthenticationLifetime());
        // tolerate missing SAML response Destination attribute https://github.com/pac4j/pac4j/pull/1871
        config.setResponseDestinationAttributeMandatory(false);

        if (getAdvancedConfiguration() != null) {

            // request forced authentication at the IdP, if selected
            config.setForceAuth(getForceAuthn());

            // override the default EntityId for this SP, if one is set
            if (getSpEntityId() != null) {
                config.setServiceProviderEntityId(getSpEntityId());
            }

            // if a specific authentication type (authentication context class
            // reference) is set, include it in the request to the IdP, and request
            // that the IdP uses exact matching for authentication types
            if (getAuthnContextClassRef() != null) {
                config.setAuthnContextClassRefs(Arrays.asList(getAuthnContextClassRef()));
                config.setComparisonType("exact");
            }

            if(getNameIdPolicyFormat() != null) {
                config.setNameIdPolicyFormat(getNameIdPolicyFormat());
            }
        }

        config.setForceServiceProviderMetadataGeneration(true);
        config.setServiceProviderMetadataResource(new SamlFileResource(SamlSecurityRealm.getSPMetadataFilePath()));
        return config;
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
