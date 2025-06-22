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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.NotImplementedException;
import org.pac4j.core.exception.TechnicalException;
import org.springframework.core.io.Resource;
import org.springframework.core.io.WritableResource;

/**
 * Class to manage the metadata files using cache.
 * It will only write the files if the content is different.
 */
class SamlFileResourceCache implements WritableResource {

    private static final Logger LOG = Logger.getLogger(SamlFileResource.class.getName());

    private String fileName;

    private static final Map<String, String> cache = new HashMap<>();

    public SamlFileResourceCache(@NonNull String fileName) {
        LOG.log(Level.FINER, "Creating Resource cache: %s", fileName);
        this.fileName = fileName;
    }

    public SamlFileResourceCache(@NonNull String fileName, @NonNull String data) {
        LOG.log(Level.FINER, "Creating Resource cache from data: %s", fileName);
        this.fileName = fileName;
        try {
            save(fileName, data);
        } catch (UnsupportedEncodingException e) {
            throw new TechnicalException("Could not get string bytes.", e);
        } catch (java.io.IOException e) {
            throw new TechnicalException("Could not save the " + fileName + " file.", e);
        }
    }

    @Override
    public boolean exists() {
        return new File(fileName).exists();
    }

    @Override
    public boolean isReadable() {
        return new File(fileName).canRead();
    }

    @Override
    public boolean isOpen() {
        return false;
    }

    @Override
    public URL getURL() throws MalformedURLException {
        return getURI().toURL();
    }

    @Override
    public URI getURI() {
        return getFile().toURI();
    }

    @Override
    public String getFilename() {
        return fileName;
    }

    @Override
    public String getDescription() {
        return fileName;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        LOG.log(Level.FINER, "Get cache inputStream : %s", fileName);
        if (cache.containsKey(fileName)) {
            return IOUtils.toInputStream(cache.get(fileName), "UTF-8");
        } else {
            return FileUtils.openInputStream(getFile());
        }
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
        return new File(fileName).canWrite();
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        LOG.log(Level.FINER, "Creating cache outputStream: %s", fileName);
        return new ByteArrayOutputStream() {
            @Override
            public void close() throws IOException {
                save(fileName, IOUtils.toString(this.buf, "UTF-8").trim());
            }
        };
    }

    private boolean isNew(String fileName, String data) {
        String oldData = cache.containsKey(fileName) ? cache.get(fileName) : "";
        String md5SumNew = org.apache.commons.codec.digest.DigestUtils.md5Hex(data);
        String md5SumOld = org.apache.commons.codec.digest.DigestUtils.md5Hex(oldData);
        return !md5SumNew.equals(md5SumOld);
    }

    private void save(@NonNull String fileName, @NonNull String data) throws IOException {
        if (isNew(fileName, data)) {
            LOG.log(Level.FINER, "Save resource to disk : %s", fileName);
            Files.write(new File(fileName).toPath(), data.getBytes("UTF-8"));
            cache.put(fileName, data);
        }
    }
}
