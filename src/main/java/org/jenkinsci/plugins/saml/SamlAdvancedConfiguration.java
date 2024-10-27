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

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_NOT_VALID_NUMBER;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Simple immutable data class to hold the optional advanced configuration data section
 * of the plugin's configuration page
 */
public class SamlAdvancedConfiguration extends AbstractDescribableImpl<SamlAdvancedConfiguration> {
    private final Boolean forceAuthn;
    private final String authnContextClassRef;
    private final String spEntityId;
    private final String nameIdPolicyFormat;

    private Boolean useDiskCache = false;

    private Boolean randomRelayState = false;

    @DataBoundConstructor
    public SamlAdvancedConfiguration(
            Boolean forceAuthn, String authnContextClassRef, String spEntityId, String nameIdPolicyFormat) {
        this.forceAuthn = (forceAuthn != null) ? forceAuthn : false;
        this.authnContextClassRef = Util.fixEmptyAndTrim(authnContextClassRef);
        this.spEntityId = Util.fixEmptyAndTrim(spEntityId);
        this.nameIdPolicyFormat = Util.fixEmptyAndTrim(nameIdPolicyFormat);
    }

    public Boolean getForceAuthn() {
        return forceAuthn;
    }

    public String getAuthnContextClassRef() {
        return authnContextClassRef;
    }

    public String getSpEntityId() {
        return spEntityId;
    }

    public String getNameIdPolicyFormat() {
        return nameIdPolicyFormat;
    }

    public Boolean getUseDiskCache() {
        return useDiskCache != null ? useDiskCache : false;
    }

    @DataBoundSetter
    public void setUseDiskCache(Boolean useDiskCache) {
        this.useDiskCache = useDiskCache;
    }

    public Boolean getRandomRelayState() {
        return randomRelayState != null ? randomRelayState : false;
    }

    @DataBoundSetter
    public void setRandomRelayState(Boolean randomRelayState) {
        this.randomRelayState = randomRelayState;
    }

    @Override
    public String toString() {
        return "SamlAdvancedConfiguration{" + "forceAuthn=" + getForceAuthn() + ", authnContextClassRef='"
                + StringUtils.defaultIfBlank(getAuthnContextClassRef(), "none") + '\'' + ", spEntityId='"
                + StringUtils.defaultIfBlank(getSpEntityId(), "none") + '\'' + ", nameIdPolicyFormat='"
                + StringUtils.defaultIfBlank(getNameIdPolicyFormat(), "none") + '\''
                + ", useDiskCache=" + getUseDiskCache()
                + ", randomRelayState=" + getRandomRelayState() + '}';
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends Descriptor<SamlAdvancedConfiguration> {
        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SamlAdvancedConfiguration> clazz) {
            super(clazz);
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Advanced Configuration";
        }

        @RequirePOST
        public FormValidation doCheckAuthnContextClassRef(
                @org.kohsuke.stapler.QueryParameter String authnContextClassRef) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringFormat(authnContextClassRef);
        }

        @RequirePOST
        public FormValidation doCheckSpEntityId(@org.kohsuke.stapler.QueryParameter String spEntityId) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringFormat(spEntityId);
        }

        @RequirePOST
        public FormValidation doCheckNameIdPolicyFormat(@org.kohsuke.stapler.QueryParameter String nameIdPolicyFormat) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringFormat(nameIdPolicyFormat);
        }

        @RequirePOST
        public FormValidation doCheckMaximumSessionLifetime(
                @org.kohsuke.stapler.QueryParameter String maximumSessionLifetime) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (StringUtils.isEmpty(maximumSessionLifetime)) {
                return hudson.util.FormValidation.ok();
            }

            long i = 0;
            try {
                i = Long.parseLong(maximumSessionLifetime);
            } catch (NumberFormatException e) {
                return hudson.util.FormValidation.error(ERROR_NOT_VALID_NUMBER, e);
            }

            if (i < 0) {
                return hudson.util.FormValidation.error(ERROR_NOT_VALID_NUMBER);
            }

            if (i > Integer.MAX_VALUE) {
                return hudson.util.FormValidation.error(ERROR_NOT_VALID_NUMBER);
            }

            return hudson.util.FormValidation.ok();
        }
    }
}
