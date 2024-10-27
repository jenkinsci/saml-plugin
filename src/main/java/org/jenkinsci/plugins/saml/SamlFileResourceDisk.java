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
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.NotImplementedException;
import org.pac4j.core.exception.TechnicalException;
import org.springframework.core.io.Resource;
import org.springframework.core.io.WritableResource;

/**
 * Class to manage the metadata files.
 */
class SamlFileResourceDisk implements WritableResource {

    private final String fileName;

    public SamlFileResourceDisk(@NonNull String fileName) {
        this.fileName = fileName;
    }

    public SamlFileResourceDisk(@NonNull String fileName, @NonNull String data) {
        this.fileName = fileName;
        try {
            Files.write(getFile().toPath(), data.getBytes(StandardCharsets.UTF_8));
        } catch (UnsupportedEncodingException e) {
            throw new TechnicalException("Could not get string bytes.", e);
        } catch (java.io.IOException e) {
            throw new TechnicalException("Could not save the " + fileName + " file.", e);
        }
    }

    @Override
    public boolean exists() {
        return getFile().exists();
    }

    @Override
    public boolean isReadable() {
        return getFile().canRead();
    }

    @Override
    public boolean isOpen() {
        return false;
    }

    @NonNull
    @Override
    public URL getURL() throws MalformedURLException {
        return getURI().toURL();
    }

    @NonNull
    @Override
    public URI getURI() {
        return getFile().toURI();
    }

    @Override
    public String getFilename() {
        return fileName;
    }

    @NonNull
    @Override
    public String getDescription() {
        return fileName;
    }

    @NonNull
    @Override
    public InputStream getInputStream() throws IOException {
        return FileUtils.openInputStream(getFile());
    }

    @NonNull
    @Override
    public File getFile() {
        return new File(fileName);
    }

    @Override
    public long contentLength() {
        return getFile().length();
    }

    @Override
    public long lastModified() {
        return getFile().lastModified();
    }

    @NonNull
    @Override
    public Resource createRelative(@NonNull String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean isWritable() {
        return getFile().canWrite();
    }

    @NonNull
    @Override
    public OutputStream getOutputStream() throws IOException {
        return Files.newOutputStream(getFile().toPath());
    }
}
