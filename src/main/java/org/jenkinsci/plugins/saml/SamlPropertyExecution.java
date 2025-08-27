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
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.config.SAML2Configuration;

/**
 * Interface for executing SAML property customizations.
 * This interface allows for customizing the SAML2 configuration and client.
 */
public interface SamlPropertyExecution {
    /**
     * Customize the SAML2 configuration.
     *
     * @param configuration      the SAML2 configuration to customize
     */
    default void customizeConfiguration(@NonNull SAML2Configuration configuration) {}

    /**
     * Customize the SAML2 client.
     * <p>
     * Always called after {@link #customizeConfiguration(SAML2Configuration)}.
     *
     * @param client             the SAML2 client to customize
     */
    default void customizeClient(@NonNull SAML2Client client) {}
}
