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

import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Logger;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.core.http.callback.NoParameterCallbackUrlResolver;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;
import static java.util.logging.Level.FINE;
import static java.util.logging.Level.SEVERE;

/**
 * Overall wrapper to all operation using OpenSAML library, this allows to load the Service Loaders properly
 * <p>
 * https://wiki.shibboleth.net/confluence/display/OS30/Initialization+and+Configuration
 * http://docs.oracle.com/javase/6/docs/api/java/util/ServiceLoader.html
 * https://stackoverflow.com/questions/37948303/opensaml3-resource-not-found-default-config-xml-in-osgi-container/39004323#39004323
 *
 * @param <T> process return type
 */
public abstract class OpenSAMLWrapper<T> {
    private static final Logger LOG = Logger.getLogger(OpenSAMLWrapper.class.getName());
    private static final BundleKeyStore KS = new BundleKeyStore();

    protected SamlPluginConfig samlPluginConfig;
    protected StaplerRequest request;
    protected StaplerResponse response;

    /**
     * Initialize the OpenSaml services and run the process defined on the abstract method process().
     *
     * @return process return object
     */
    public T get() {
        T ret = null;
        try {
            LOG.finest("adapt TCCL");
            Thread thread = Thread.currentThread();
            ClassLoader loader = thread.getContextClassLoader();
            thread.setContextClassLoader(InitializationService.class.getClassLoader());
            try {
                InitializationService.initialize();
                ret = process();
            } finally {
                LOG.finest("reset TCCL");
                thread.setContextClassLoader(loader);
            }
        } catch (InitializationException e) {
            LOG.log(SEVERE, "Could not initialize opensaml service.", e);
            throw new IllegalStateException(e);
        }
        return ret;
    }

    /**
     * Process to run using the OpenSaml services.
     *
     * @return process return type
     */
    abstract protected T process();

    /**
     * @return J2E Context from the current HTTP request and response.
     */
    protected WebContext createWebContext() {
        return new JEEContext(request, response);
    }

    /**
     * @return a SAML2Client object to interact with the IdP service.
     */
    protected SAML2Client createSAML2Client() {
        SAML2Configuration config = new SAML2Configuration();
        config.setIdentityProviderMetadataResource(new SamlFileResource(SamlSecurityRealm.getIDPMetadataFilePath()));
        config.setAuthnRequestBindingType(samlPluginConfig.getBinding());

        SamlEncryptionData encryptionData = samlPluginConfig.getEncryptionData();
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
            config.setKeystoreAlias(encryptionData.getPrivateKeyAlias());
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
            config.setKeystoreAlias(KS.getKsPkAlias());
        }

        config.setMaximumAuthenticationLifetime(samlPluginConfig.getMaximumAuthenticationLifetime());

        if (samlPluginConfig.getAdvancedConfiguration() != null) {

            // request forced authentication at the IdP, if selected
            config.setForceAuth(samlPluginConfig.getForceAuthn());

            // override the default EntityId for this SP, if one is set
            if (samlPluginConfig.getSpEntityId() != null) {
                config.setServiceProviderEntityId(samlPluginConfig.getSpEntityId());
            }

            // if a specific authentication type (authentication context class
            // reference) is set, include it in the request to the IdP, and request
            // that the IdP uses exact matching for authentication types
            if (samlPluginConfig.getAuthnContextClassRef() != null) {
                config.setAuthnContextClassRefs(Arrays.asList(samlPluginConfig.getAuthnContextClassRef()));
                config.setComparisonType("exact");
            }

            if(samlPluginConfig.getNameIdPolicyFormat() != null) {
                config.setNameIdPolicyFormat(samlPluginConfig.getNameIdPolicyFormat());
            }
        }

        config.setForceServiceProviderMetadataGeneration(true);
        config.setServiceProviderMetadataResource(new SamlFileResource(SamlSecurityRealm.getSPMetadataFilePath()));
        SAML2Client saml2Client = new SAML2Client(config);
        saml2Client.setCallbackUrl(samlPluginConfig.getConsumerServiceUrl());
        saml2Client.setCallbackUrlResolver(new NoParameterCallbackUrlResolver());
        saml2Client.init();

        if (LOG.isLoggable(FINE)) {
            try {
                LOG.fine(saml2Client.getServiceProviderMetadataResolver().getMetadata());
            } catch (TechnicalException e) {
                LOG.fine("Is not possible to show the metadata : " + e.getMessage());
            }
        }
        return saml2Client;
    }

}
