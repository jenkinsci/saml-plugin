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
import org.springframework.core.io.WritableResource;

/**
 * Static factory methods to create {@link WritableResource} instances for SAML file resources.
 */
final class SamlFileResourceFactory {

    public static WritableResource create(@NonNull String fileName, boolean useDiskCache) {
        if (useDiskCache) {
            return new SamlFileResourceCache(fileName);
        } else {
            return new SamlFileResourceDisk(fileName);
        }
    }

    public static WritableResource create(@NonNull String fileName, @NonNull String data, boolean useDiskCache) {
        if (useDiskCache) {
            return new SamlFileResourceCache(fileName, data);
        } else {
            return new SamlFileResourceDisk(fileName, data);
        }
    }
}
