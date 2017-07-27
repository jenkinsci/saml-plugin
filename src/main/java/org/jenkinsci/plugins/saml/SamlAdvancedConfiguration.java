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

import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Simple immutable data class to hold the optional advanced configuration data section
 * of the plugin's configuration page
 */
public class SamlAdvancedConfiguration {
    private final Boolean forceAuthn;
    private final String authnContextClassRef;
    private final String spEntityId;
    private final Integer maximumSessionLifetime;

    @DataBoundConstructor
    public SamlAdvancedConfiguration(Boolean forceAuthn, String authnContextClassRef, String spEntityId, Integer maximumSessionLifetime) {
        this.forceAuthn = (forceAuthn != null) ? forceAuthn : false;
        this.authnContextClassRef = Util.fixEmptyAndTrim(authnContextClassRef);
        this.spEntityId = Util.fixEmptyAndTrim(spEntityId);
        this.maximumSessionLifetime = maximumSessionLifetime;
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

    public Integer getMaximumSessionLifetime() {
        return maximumSessionLifetime;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("SamlAdvancedConfiguration{");
        sb.append("forceAuthn=").append(forceAuthn);
        sb.append(", authnContextClassRef='").append(StringUtils.defaultIfBlank(authnContextClassRef, "none")).append('\'');
        sb.append(", spEntityId='").append(StringUtils.defaultIfBlank(spEntityId, "none")).append('\'');
        sb.append(", maximumSessionLifetime=").append(maximumSessionLifetime != null ? maximumSessionLifetime : "none");
        sb.append('}');
        return sb.toString();
    }
}