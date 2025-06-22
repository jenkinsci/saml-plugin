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
package org.jenkinsci.plugins.saml.user;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.saml.SamlSecurityRealm;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest2;

/**
 * Store custom SAMl Attributes read from SAML Response.
 *
 * @author Kuisathaverat
 */
public class SamlCustomProperty extends UserProperty {
    /**
     * list of custom Attributes.
     */
    List<Attribute> attributes;

    public static class Attribute extends AbstractDescribableImpl<Attribute> {

        /**
         * Name of the attribute in the SAML Response.
         */
        private final String name;
        /**
         * Name to display as attribute's value label on the user profile.
         */
        private final String displayName;
        /**
         * value of the attribute.
         */
        private String value;

        public Attribute(String name, String displayName) {
            this.name = name;
            this.displayName = displayName;
        }

        @SuppressWarnings("unused")
        public String getName() {
            return name;
        }

        @SuppressWarnings("unused")
        public String getDisplayName() {
            return displayName;
        }

        @SuppressWarnings("unused")
        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Attribute attribute = (Attribute) o;
            return Objects.equals(name, attribute.name)
                    && Objects.equals(displayName, attribute.displayName)
                    && Objects.equals(value, attribute.value);
        }

        @Override
        public int hashCode() {

            return Objects.hash(name, displayName, value);
        }

        @SuppressWarnings("unused")
        @Extension
        public static final class DescriptorImpl extends Descriptor<Attribute> {
            @NonNull
            @Override
            public String getDisplayName() {
                return "SAML Attribute";
            }
        }
    }

    @DataBoundConstructor
    public SamlCustomProperty(List<Attribute> attributes) {
        this.attributes = attributes;
    }

    @NonNull
    public List<Attribute> getAttributes() {
        if (attributes == null) {
            return java.util.Collections.emptyList();
        }
        return attributes;
    }

    @SuppressWarnings("unused")
    public void setAttributes(List<Attribute> attributes) {
        this.attributes = attributes;
    }

    @Override
    public UserProperty reconfigure(StaplerRequest2 req, JSONObject form) {
        return this;
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @NonNull
        public String getDisplayName() {
            return "Saml Custom Attributes property";
        }

        public SamlCustomProperty newInstance(User user) {
            return new SamlCustomProperty(new ArrayList<>());
        }

        @Override
        public boolean isEnabled() {
            return Jenkins.get().getSecurityRealm() instanceof SamlSecurityRealm;
        }
    }
}
