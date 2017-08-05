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
import org.kohsuke.stapler.DataBoundConstructor;

import org.apache.commons.lang.StringUtils;

/**
 * Simple immutable data class to hold the optional encryption data section
 * of the plugin's configuration page
 */
public class SamlEncryptionData {
    private final String keystorePath;
    private final Secret keystorePassword;
    private final Secret privateKeyPassword;
    private final String privateKeyAlias;

    @DataBoundConstructor
    public SamlEncryptionData(String keystorePath, String keystorePassword, String privateKeyPassword, String privateKeyAlias) {
        this.keystorePath = Util.fixEmptyAndTrim(keystorePath);
        this.keystorePassword = Secret.fromString(Util.fixEmpty(keystorePassword));
        this.privateKeyPassword = Secret.fromString(Util.fixEmpty(privateKeyPassword));
        this.privateKeyAlias = Util.fixEmptyAndTrim(privateKeyAlias);
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getKeystorePassword() {
        return Secret.toString(keystorePassword);
    }

    public String getPrivateKeyPassword() {
        return Secret.toString(privateKeyPassword);
    }

    public String getPrivateKeyAlias() {
        return privateKeyAlias;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SamlEncryptionData{");
        sb.append("keystorePath='").append(StringUtils.defaultIfBlank(getKeystorePath(), "none")).append('\'');
        sb.append(", keystorePassword is NOT empty='").append(StringUtils.isNotEmpty(getKeystorePassword())).append('\'');
        sb.append(", privateKeyPassword is NOT empty='").append(StringUtils.isNotEmpty(getPrivateKeyPassword())).append('\'');
        sb.append(", privateKeyAlias is NOT empty='").append(StringUtils.isNotEmpty(getPrivateKeyAlias())).append('\'');
        sb.append('}');
        return sb.toString();
    }
}