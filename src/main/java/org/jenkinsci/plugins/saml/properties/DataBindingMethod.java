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

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.Util;
import hudson.util.ListBoxModel;
import java.util.Objects;
import java.util.Optional;
import org.jenkinsci.plugins.saml.SamlProperty;
import org.jenkinsci.plugins.saml.SamlPropertyDescriptor;
import org.jenkinsci.plugins.saml.SamlPropertyExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.saml.config.SAML2Configuration;

/**
 * Represents the data binding method for SAML authentication.
 */
public class DataBindingMethod extends SamlProperty {
    public static final String HTTP_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    public static final String HTTP_POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    private final String value;

    @DataBoundConstructor
    public DataBindingMethod(@CheckForNull String value) {
        // TODO validate value against known bindings
        this.value =
                Objects.requireNonNull(Util.fixEmptyAndTrim(value), "Data Binding Method must not be null or empty");
    }

    @NonNull
    public String getValue() {
        return value;
    }

    @NonNull
    public static Optional<DataBindingMethod> getPropertyFor(String value) {
        if (value == null || value.isEmpty() || HTTP_REDIRECT_BINDING.equals(value)) {
            return Optional.empty();
        }
        return Optional.of(new DataBindingMethod(HTTP_POST_BINDING));
    }

    @NonNull
    @Override
    public SamlPropertyExecution newExecution() {
        return new ExecutionImpl(value);
    }

    private record ExecutionImpl(@NonNull String value) implements SamlPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull SAML2Configuration configuration) {
            configuration.setAuthnRequestBindingType(value);
        }
    }

    @Extension
    public static class DescriptorImpl extends SamlPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Data Binding Method";
        }

        public String getValue() {
            return HTTP_REDIRECT_BINDING;
        }

        @Override
        public void getDefaultConfiguration(@NonNull SAML2Configuration configuration) {
            configuration.setAuthnRequestBindingType(HTTP_REDIRECT_BINDING);
        }

        @SuppressWarnings("unused") // stapler
        public ListBoxModel doFillValueItems() {
            ListBoxModel items = new ListBoxModel();
            items.add("HTTP-Redirect", HTTP_REDIRECT_BINDING);
            items.add("HTTP-POST", HTTP_POST_BINDING);
            return items;
        }
    }
}
