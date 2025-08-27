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

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_ALGORITHM_CANNOT_BE_FOUND;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_CERTIFICATES_COULD_NOT_BE_LOADED;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_INSUFFICIENT_OR_INVALID_INFO;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_NOT_KEY_FOUND;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_NOT_POSSIBLE_TO_READ_KS_FILE;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_NO_PROVIDER_SUPPORTS_A_KS_SPI_IMPL;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_WRONG_INFO_OR_PASSWORD;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.SUCCESS;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.WARN_KEYSTORE_NOT_SET;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.WARN_PRIVATE_KEYSTORE_PASS_NOT_SET;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.WARN_PRIVATE_KEY_ALIAS_NOT_SET;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.WARN_PRIVATE_KEY_PASS_NOT_SET;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.WARN_THERE_IS_NOT_KEY_STORE;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import hudson.util.Secret;
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
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Simple immutable data class to hold the optional encryption data section
 * of the plugin's configuration page
 */
public class SamlEncryptionData extends AbstractDescribableImpl<SamlEncryptionData> {
    private final String keystorePath;
    private Secret keystorePasswordSecret;
    private Secret privateKeyPasswordSecret;
    private final String privateKeyAlias;
    private final boolean forceSignRedirectBindingAuthnRequest;
    private boolean wantsAssertionsSigned;

    @DataBoundConstructor
    public SamlEncryptionData(
            String keystorePath,
            Secret keystorePassword,
            Secret privateKeyPassword,
            String privateKeyAlias,
            boolean forceSignRedirectBindingAuthnRequest,
            boolean wantsAssertionsSigned) {
        this.keystorePath = Util.fixEmptyAndTrim(keystorePath);
        if (keystorePassword != null && StringUtils.isNotEmpty(keystorePassword.getPlainText())) {
            this.keystorePasswordSecret = keystorePassword;
        }
        if (privateKeyPassword != null && StringUtils.isNotEmpty(privateKeyPassword.getPlainText())) {
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

    @SuppressWarnings("unused")
    public void setWantsAssertionsSigned(boolean wantsAssertionsSigned) {
        this.wantsAssertionsSigned = wantsAssertionsSigned;
    }

    @Override
    public String toString() {
        return "SamlEncryptionData{" + "keystorePath='" + StringUtils.defaultIfBlank(keystorePath, "none") + '\''
                + ", keystorePassword is NOT empty='" + (getKeystorePasswordPlainText() != null) + '\''
                + ", privateKeyPassword is NOT empty='" + (getPrivateKeyPasswordPlainText() != null) + '\''
                + ", privateKeyAlias is NOT empty='" + StringUtils.isNotEmpty(privateKeyAlias) + '\''
                + ", forceSignRedirectBindingAuthnRequest = " + forceSignRedirectBindingAuthnRequest
                + ", wantsAssertionsSigned = " + wantsAssertionsSigned + '}';
    }

    @SuppressWarnings("unused")
    private Object readResolve() {
        return this;
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends Descriptor<SamlEncryptionData> {
        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SamlEncryptionData> clazz) {
            super(clazz);
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Encryption Configuration";
        }

        @RequirePOST
        public FormValidation doCheckKeystorePath(@QueryParameter String keystorePath) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringAttributeFormat(keystorePath, WARN_KEYSTORE_NOT_SET, true);
        }

        @RequirePOST
        public FormValidation doCheckPrivateKeyAlias(@QueryParameter String privateKeyAlias) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringAttributeFormat(privateKeyAlias, WARN_PRIVATE_KEY_ALIAS_NOT_SET, true);
        }

        @RequirePOST
        public FormValidation doCheckKeystorePassword(@QueryParameter String keystorePassword) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringAttributeFormat(
                    keystorePassword, WARN_PRIVATE_KEYSTORE_PASS_NOT_SET, true);
        }

        @RequirePOST
        public FormValidation doCheckPrivateKeyPassword(@QueryParameter String privateKeyPassword) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringAttributeFormat(
                    privateKeyPassword, WARN_PRIVATE_KEY_PASS_NOT_SET, true);
        }

        @RequirePOST
        public FormValidation doTestKeyStore(
                @QueryParameter("keystorePath") String keystorePath,
                @QueryParameter("keystorePassword") Secret keystorePassword,
                @QueryParameter("privateKeyPassword") Secret privateKeyPassword,
                @QueryParameter("privateKeyAlias") String privateKeyAlias) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (StringUtils.isBlank(keystorePath)) {
                return FormValidation.warning(WARN_THERE_IS_NOT_KEY_STORE);
            }
            try (InputStream in = new FileInputStream(keystorePath)) {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(in, keystorePassword.getPlainText().toCharArray());

                KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(null);
                if (StringUtils.isNotBlank(privateKeyPassword.getPlainText())) {
                    keyPassword = new KeyStore.PasswordProtection(
                            privateKeyPassword.getPlainText().toCharArray());
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
