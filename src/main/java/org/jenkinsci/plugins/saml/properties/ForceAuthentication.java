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
import org.jenkinsci.plugins.saml.SamlProperty;
import org.jenkinsci.plugins.saml.SamlPropertyDescriptor;
import org.jenkinsci.plugins.saml.SamlPropertyExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.pac4j.saml.config.SAML2Configuration;

/**
 * When this property is included, it will force the SAML authentication to always require user authentication.
 */
public class ForceAuthentication extends SamlProperty {
    @DataBoundConstructor
    public ForceAuthentication() {}

    @NonNull
    @Override
    public SamlPropertyExecution newExecution() {
        return new ExecutionImpl();
    }

    private record ExecutionImpl() implements SamlPropertyExecution {
        @Override
        public void customizeConfiguration(@NonNull SAML2Configuration configuration) {
            configuration.setForceAuth(true);
        }
    }

    @Extension
    public static class DescriptorImpl extends SamlPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Force Authentication";
        }
    }
}
