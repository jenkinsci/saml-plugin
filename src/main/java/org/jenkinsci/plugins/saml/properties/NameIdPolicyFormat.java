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

package org.jenkinsci.plugins.saml.properties;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.FormValidation;
import java.util.Objects;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.saml.SamlFormValidation;
import org.jenkinsci.plugins.saml.SamlProperty;
import org.jenkinsci.plugins.saml.SamlPropertyDescriptor;
import org.jenkinsci.plugins.saml.SamlPropertyExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.pac4j.saml.config.SAML2Configuration;

/**
 * Represents the Name ID Policy Format for SAML authentication.
 * This property allows specifying the format of the Name ID policy.
 */
public class NameIdPolicyFormat extends SamlProperty {
    @NonNull
    private final String value;

    @DataBoundConstructor
    public NameIdPolicyFormat(String value) {
        this.value =
                Objects.requireNonNull(Util.fixEmptyAndTrim(value), "Name ID Policy Format must not be null or empty");
    }

    @NonNull
    public String getValue() {
        return value;
    }

    @NonNull
    @Override
    public SamlPropertyExecution newExecution() {
        return new ExecutionImpl(value);
    }

    private record ExecutionImpl(@NonNull String value) implements SamlPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull SAML2Configuration configuration) {
            configuration.setNameIdPolicyFormat(value);
        }
    }

    @Extension
    public static class DescriptorImpl extends SamlPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Name ID Policy Format";
        }

        @RequirePOST
        @SuppressWarnings("unused") // stapler
        public FormValidation doCheckValue(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringFormat(value);
        }
    }
}
