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
import javax.annotation.Nonnull;

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

    @DataBoundConstructor
    public SamlEncryptionData(String keystorePath, Secret keystorePassword, Secret privateKeyPassword, String privateKeyAlias,
                              boolean forceSignRedirectBindingAuthnRequest) {
        this.keystorePath = Util.fixEmptyAndTrim(keystorePath);
        this.keystorePasswordSecret = keystorePassword != null ? keystorePassword : Secret.fromString("");
        this.privateKeyPasswordSecret = privateKeyPassword != null ? privateKeyPassword : Secret.fromString("");
        this.privateKeyAlias = Util.fixEmptyAndTrim(privateKeyAlias);
        this.forceSignRedirectBindingAuthnRequest = forceSignRedirectBindingAuthnRequest;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public @Nonnull Secret getKeystorePassword() {
        return keystorePasswordSecret;
    }

    public @CheckForNull String getKeystorePasswordPlainText() {
        return Util.fixEmptyAndTrim(keystorePasswordSecret.getPlainText());
    }

    public @Nonnull Secret getPrivateKeyPassword() {
        return privateKeyPasswordSecret;
    }

    public @CheckForNull String getPrivateKeyPasswordPlainText() {
        return Util.fixEmptyAndTrim(privateKeyPasswordSecret.getPlainText());
    }

    public String getPrivateKeyAlias() {
        return privateKeyAlias;
    }

    public boolean isForceSignRedirectBindingAuthnRequest() {
        return forceSignRedirectBindingAuthnRequest;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SamlEncryptionData{");
        sb.append("keystorePath='").append(StringUtils.defaultIfBlank(keystorePath, "none")).append('\'');
        sb.append(", keystorePassword is NOT empty='").append(getKeystorePasswordPlainText() != null).append('\'');
        sb.append(", privateKeyPassword is NOT empty='").append(getPrivateKeyPasswordPlainText() != null).append('\'');
        sb.append(", privateKeyAlias is NOT empty='").append(StringUtils.isNotEmpty(privateKeyAlias)).append('\'');
        sb.append(", forceSignRedirectBindingAuthnRequest = ").append(forceSignRedirectBindingAuthnRequest);
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
            if (StringUtils.isEmpty(keystorePath)) {
                return FormValidation.ok();
            }

            if (StringUtils.isBlank(keystorePath)) {
                return FormValidation.error(ERROR_ONLY_SPACES_FIELD_VALUE);
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckPrivateKeyAlias(@QueryParameter String privateKeyAlias) {
            if (StringUtils.isEmpty(privateKeyAlias)) {
                return FormValidation.ok();
            }

            if (StringUtils.isBlank(privateKeyAlias)) {
                return FormValidation.error(ERROR_ONLY_SPACES_FIELD_VALUE);
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckKeystorePassword(@QueryParameter String keystorePassword) {
            if (StringUtils.isEmpty(keystorePassword)) {
                return FormValidation.ok();
            }

            if (StringUtils.isBlank(keystorePassword)) {
                return FormValidation.error(ERROR_ONLY_SPACES_FIELD_VALUE);
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckPrivateKeyPassword(@QueryParameter String privateKeyPassword) {
            if (StringUtils.isEmpty(privateKeyPassword)) {
                return FormValidation.ok();
            }

            if (StringUtils.isBlank(privateKeyPassword)) {
                return FormValidation.error(ERROR_ONLY_SPACES_FIELD_VALUE);
            }

            return FormValidation.ok();
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
