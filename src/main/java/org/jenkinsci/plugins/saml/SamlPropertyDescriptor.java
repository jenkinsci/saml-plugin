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

import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.model.Descriptor;

/**
 * Descriptor for SAML properties.
 * It also implements directly {@link SamlPropertyExecution} so that it can be used to decorate configuration and client even if not explicitly configured.
 */
public abstract class SamlPropertyDescriptor extends Descriptor<SamlProperty> implements ExtensionPoint {
    /**
     * @return all registered {@link SamlPropertyDescriptor} instances.
     */
    public static ExtensionList<SamlPropertyDescriptor> all() {
        return ExtensionList.lookup(SamlPropertyDescriptor.class);
    }
}
