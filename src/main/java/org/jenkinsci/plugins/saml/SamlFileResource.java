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

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.NotImplementedException;
import org.pac4j.core.exception.TechnicalException;
import org.springframework.core.io.Resource;
import org.springframework.core.io.WritableResource;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.util.logging.Logger;

/**
 * Class to manage the metadata files.
 */
class SamlFileResource implements WritableResource {

    private static final Logger LOG = Logger.getLogger(SamlFileResource.class.getName());

    private String fileName;

    private byte[] data;

    public SamlFileResource(@Nonnull String fileName) {
        this.fileName = fileName;
    }

    public SamlFileResource(@Nonnull String fileName, @Nonnull String data) {
        this.fileName = fileName;
        try {
            this.data = data.getBytes("UTF-8");
            FileUtils.writeByteArrayToFile(getFile(), this.data);
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

    @Override
    public URL getURL() {
        throw new NotImplementedException();
    }

    @Override
    public URI getURI() {
        throw new NotImplementedException();
    }

    @Override
    public String getFilename() {
        return fileName;
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return FileUtils.openInputStream(getFile());
    }

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

    @Override
    public Resource createRelative(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean isWritable() {
        return getFile().canWrite();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return FileUtils.openOutputStream(getFile());
    }
}
