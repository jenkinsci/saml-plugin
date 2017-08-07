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

import hudson.Util;
import hudson.util.Secret;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import org.kohsuke.stapler.DataBoundConstructor;

import org.apache.commons.lang.StringUtils;

/**
 * Simple immutable data class to hold the optional encryption data section
 * of the plugin's configuration page
 */
public class SamlEncryptionData {
    private final String keystorePath;
    @Deprecated
    private transient String keystorePassword;
    private Secret keystorePasswordSecret;
    @Deprecated
    private transient String privateKeyPassword;
    private Secret privateKeyPasswordSecret;
    private final String privateKeyAlias;

    @DataBoundConstructor
    public SamlEncryptionData(String keystorePath, Secret keystorePassword, Secret privateKeyPassword, String privateKeyAlias) {
        this.keystorePath = Util.fixEmptyAndTrim(keystorePath);
        this.keystorePasswordSecret = keystorePassword != null ? keystorePassword : Secret.fromString("");
        this.privateKeyPasswordSecret = privateKeyPassword != null ? privateKeyPassword : Secret.fromString("");
        this.privateKeyAlias = Util.fixEmptyAndTrim(privateKeyAlias);
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

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SamlEncryptionData{");
        sb.append("keystorePath='").append(StringUtils.defaultIfBlank(keystorePath, "none")).append('\'');
        sb.append(", keystorePassword is NOT empty='").append(getKeystorePasswordPlainText() != null).append('\'');
        sb.append(", privateKeyPassword is NOT empty='").append(getPrivateKeyPasswordPlainText() != null).append('\'');
        sb.append(", privateKeyAlias is NOT empty='").append(StringUtils.isNotEmpty(privateKeyAlias)).append('\'');
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

}