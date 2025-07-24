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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.AbstractDescribableImpl;

/**
 * Represents a property that can be configured for SAML authentication.
 */
public abstract class SamlProperty extends AbstractDescribableImpl<SamlProperty> {
    /**
     * @return a new execution for this property, holding any required state.
     */
    @NonNull
    public abstract SamlPropertyExecution newExecution();

    @Override
    public SamlPropertyDescriptor getDescriptor() {
        return (SamlPropertyDescriptor) super.getDescriptor();
    }
}
