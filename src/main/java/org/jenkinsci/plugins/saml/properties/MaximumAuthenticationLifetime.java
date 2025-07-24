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
import hudson.util.FormValidation;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
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
 * Represents the maximum authentication lifetime for SAML authentication.
 * This property allows specifying the maximum duration for which an authentication is valid.
 * It defaults to 1 day (86400 seconds) if not specified or set to zero.
 */
public class MaximumAuthenticationLifetime extends SamlProperty {
    public static final long DEFAULT_VALUE = TimeUnit.DAYS.toSeconds(1);
    private final long value;

    @DataBoundConstructor
    public MaximumAuthenticationLifetime(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }

    public static Optional<MaximumAuthenticationLifetime> getPropertyFor(long value) {
        if (value <= 0 || value == DEFAULT_VALUE) {
            return Optional.empty();
        } else {
            return Optional.of(new MaximumAuthenticationLifetime(value));
        }
    }

    @NonNull
    @Override
    public SamlPropertyExecution newExecution() {
        return new ExecutionImpl(value);
    }

    private record ExecutionImpl(long value) implements SamlPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull SAML2Configuration configuration) {
            configuration.setMaximumAuthenticationLifetime(value);
        }
    }

    @Extension
    public static class DescriptorImpl extends SamlPropertyDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Maximum Authentication Lifetime";
        }

        public long getValue() {
            return DEFAULT_VALUE;
        }

        @Override
        public void getDefaultConfiguration(@NonNull SAML2Configuration configuration) {
            configuration.setMaximumAuthenticationLifetime(getValue());
        }

        @RequirePOST
        public FormValidation doCheckValue(@QueryParameter String value) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkIntegerFormat(value);
        }
    }
}
