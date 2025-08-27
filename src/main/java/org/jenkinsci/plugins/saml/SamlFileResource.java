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
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import org.apache.commons.lang.NotImplementedException;
import org.springframework.core.io.Resource;
import org.springframework.core.io.WritableResource;

/**
 * Class to manage the metadata files.
 */
class SamlFileResource implements WritableResource {

    private final WritableResource resource;

    public SamlFileResource(@NonNull String fileName) {
        if (getUseDiskCache()) {
            this.resource = new SamlFileResourceCache(fileName);
        } else {
            this.resource = new SamlFileResourceDisk(fileName);
        }
    }

    public SamlFileResource(@NonNull String fileName, @NonNull String data) {
        if (getUseDiskCache()) {
            this.resource = new SamlFileResourceCache(fileName, data);
        } else {
            this.resource = new SamlFileResourceDisk(fileName, data);
        }
    }

    private boolean getUseDiskCache() {
        boolean ret = false;
        jenkins.model.Jenkins j = jenkins.model.Jenkins.get();
        if (j.getSecurityRealm() instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) j.getSecurityRealm();
            SamlAdvancedConfiguration config = samlSecurityRealm.getAdvancedConfiguration();
            if (config != null) {
                ret = config.getUseDiskCache();
            }
        }
        return ret;
    }

    @Override
    public boolean exists() {
        return resource.exists();
    }

    @Override
    public boolean isReadable() {
        return resource.isReadable();
    }

    @Override
    public boolean isOpen() {
        return false;
    }

    @NonNull
    @Override
    public URL getURL() throws IOException {
        return resource.getURL();
    }

    @NonNull
    @Override
    public URI getURI() throws IOException {
        return resource.getURI();
    }

    @Override
    public String getFilename() {
        return resource.getFilename();
    }

    @NonNull
    @Override
    public String getDescription() {
        return resource.getDescription();
    }

    @NonNull
    @Override
    public InputStream getInputStream() throws IOException {
        return resource.getInputStream();
    }

    @NonNull
    @Override
    public File getFile() throws IOException {
        return resource.getFile();
    }

    @Override
    public long contentLength() throws IOException {
        return resource.contentLength();
    }

    @Override
    public long lastModified() throws IOException {
        return resource.lastModified();
    }

    @NonNull
    @Override
    public Resource createRelative(@NonNull String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean isWritable() {
        return resource.isWritable();
    }

    @NonNull
    @Override
    public OutputStream getOutputStream() throws IOException {
        return resource.getOutputStream();
    }
}
