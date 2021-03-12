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

import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
import javax.annotation.CheckForNull;

import org.kohsuke.stapler.DataBoundConstructor;

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.QueryParameter;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.*;

/**
 * Simple immutable data class to hold the optional encryption data section
 * of the plugin's configuration page
 */
public class SamlEncryptionData extends AbstractDescribableImpl<SamlEncryptionData> {
    private final String keystorePath;
    /***
     * @deprecated use keystorePasswordSecret instead
     */
    @Deprecated
    private transient String keystorePassword;
    private Secret keystorePasswordSecret;
    /***
     * @deprecated use privateKeyPasswordSecret instead
     */
    @Deprecated
    private transient String privateKeyPassword;
    private Secret privateKeyPasswordSecret;
    private final String privateKeyAlias;
    private boolean forceSignRedirectBindingAuthnRequest;
    private boolean wantsAssertionsSigned;

    @DataBoundConstructor
    public SamlEncryptionData(String keystorePath, Secret keystorePassword, Secret privateKeyPassword, String privateKeyAlias,
                              boolean forceSignRedirectBindingAuthnRequest, boolean wantsAssertionsSigned) {
        this.keystorePath = Util.fixEmptyAndTrim(keystorePath);
        if(keystorePassword != null && StringUtils.isNotEmpty(keystorePassword.getPlainText())){
            this.keystorePasswordSecret = keystorePassword;
        }
        if(privateKeyPassword != null && StringUtils.isNotEmpty(privateKeyPassword.getPlainText())){
            this.privateKeyPasswordSecret = privateKeyPassword;
        }
        this.privateKeyAlias = Util.fixEmptyAndTrim(privateKeyAlias);
        this.forceSignRedirectBindingAuthnRequest = forceSignRedirectBindingAuthnRequest;
        this.wantsAssertionsSigned = wantsAssertionsSigned;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public @CheckForNull Secret getKeystorePassword() {
        return keystorePasswordSecret;
    }

    public @CheckForNull String getKeystorePasswordPlainText() {
        return keystorePasswordSecret != null ? Util.fixEmptyAndTrim(keystorePasswordSecret.getPlainText()) : null;
    }

    public @CheckForNull Secret getPrivateKeyPassword() {
        return privateKeyPasswordSecret;
    }

    public @CheckForNull String getPrivateKeyPasswordPlainText() {
        return privateKeyPasswordSecret != null ? Util.fixEmptyAndTrim(privateKeyPasswordSecret.getPlainText()) : null;
    }

    public String getPrivateKeyAlias() {
        return privateKeyAlias;
    }

    public boolean isForceSignRedirectBindingAuthnRequest() {
        return forceSignRedirectBindingAuthnRequest;
    }

    public boolean isWantsAssertionsSigned() {
        return wantsAssertionsSigned;
    }

    public void setWantsAssertionsSigned(boolean wantsAssertionsSigned) {
        this.wantsAssertionsSigned = wantsAssertionsSigned;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SamlEncryptionData{");
        sb.append("keystorePath='").append(StringUtils.defaultIfBlank(keystorePath, "none")).append('\'');
        sb.append(", keystorePassword is NOT empty='").append(getKeystorePasswordPlainText() != null).append('\'');
        sb.append(", privateKeyPassword is NOT empty='").append(getPrivateKeyPasswordPlainText() != null).append('\'');
        sb.append(", privateKeyAlias is NOT empty='").append(StringUtils.isNotEmpty(privateKeyAlias)).append('\'');
        sb.append(", forceSignRedirectBindingAuthnRequest = ").append(forceSignRedirectBindingAuthnRequest);
        sb.append(", wantsAssertionsSigned = ").append(wantsAssertionsSigned);
        sb.append('}');
        return sb.toString();
    }

    private Object readResolve() {
        if (keystorePassword != null) {
            keystorePasswordSecret = Secret.fromString(keystorePassword);
            keystorePassword = null;
        }
        if (privateKeyPassword != null) {
            privateKeyPasswordSecret = Secret.fromString(privateKeyPassword);
            privateKeyPassword = null;
        }
        return this;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SamlEncryptionData> {
        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SamlEncryptionData> clazz) {
            super(clazz);
        }

        @Override
        public String getDisplayName() {
            return "Encryption Configuration";
        }

        public FormValidation doCheckKeystorePath(@QueryParameter String keystorePath) {
            return SamlFormValidation.checkStringAttributeFormat(keystorePath, WARN_KEYSTORE_NOT_SET, true);
        }

        public FormValidation doCheckPrivateKeyAlias(@QueryParameter String privateKeyAlias) {
            return SamlFormValidation.checkStringAttributeFormat(privateKeyAlias, WARN_PRIVATE_KEY_ALIAS_NOT_SET, true);
        }

        public FormValidation doCheckKeystorePassword(@QueryParameter String keystorePassword) {
            return SamlFormValidation.checkStringAttributeFormat(keystorePassword, WARN_PRIVATE_KEYSTORE_PASS_NOT_SET, true);
        }

        public FormValidation doCheckPrivateKeyPassword(@QueryParameter String privateKeyPassword) {
            return SamlFormValidation.checkStringAttributeFormat(privateKeyPassword, WARN_PRIVATE_KEY_PASS_NOT_SET, true);
        }

        public FormValidation doTestKeyStore(@QueryParameter("keystorePath") String keystorePath,
                                                         @QueryParameter("keystorePassword") Secret keystorePassword,
                                                         @QueryParameter("privateKeyPassword") Secret privateKeyPassword,
                                                         @QueryParameter("privateKeyAlias") String privateKeyAlias) {
            if (StringUtils.isBlank(keystorePath)) {
                return FormValidation.warning(WARN_THERE_IS_NOT_KEY_STORE);
            }
            try (InputStream in = new FileInputStream(keystorePath)) {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(in, keystorePassword.getPlainText().toCharArray());

                KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(null);
                if (StringUtils.isNotBlank(privateKeyPassword.getPlainText())) {
                    keyPassword = new KeyStore.PasswordProtection(privateKeyPassword.getPlainText().toCharArray());
                }

                Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String currentAlias = aliases.nextElement();
                    if (StringUtils.isBlank(privateKeyAlias) || currentAlias.equalsIgnoreCase(privateKeyAlias)) {
                        ks.getEntry(currentAlias, keyPassword);
                        return FormValidation.ok(SUCCESS);
                    }
                }

            } catch (IOException e) {
                return FormValidation.error(e, ERROR_NOT_POSSIBLE_TO_READ_KS_FILE);
            } catch (CertificateException e) {
                return FormValidation.error(e, ERROR_CERTIFICATES_COULD_NOT_BE_LOADED);
            } catch (NoSuchAlgorithmException e) {
                return FormValidation.error(e, ERROR_ALGORITHM_CANNOT_BE_FOUND);
            } catch (KeyStoreException e) {
                return FormValidation.error(e, ERROR_NO_PROVIDER_SUPPORTS_A_KS_SPI_IMPL);
            } catch (UnrecoverableKeyException e) {
                return FormValidation.error(e, ERROR_WRONG_INFO_OR_PASSWORD);
            } catch (UnrecoverableEntryException e) {
                return FormValidation.error(e, ERROR_INSUFFICIENT_OR_INVALID_INFO);
            }
            return FormValidation.error(ERROR_NOT_KEY_FOUND);
        }

    }
}
