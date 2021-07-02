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
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.NotImplementedException;
import org.pac4j.core.exception.TechnicalException;
import org.springframework.core.io.Resource;
import org.springframework.core.io.WritableResource;

import javax.annotation.Nonnull;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Class to manage the metadata files.
 */
class SamlFileResource implements WritableResource {

    private static final Logger LOG = Logger.getLogger(SamlFileResource.class.getName());

    private String fileName;

    private final static Map<String,String> cache = new HashMap<>();

    public SamlFileResource(@Nonnull String fileName) {
        this.fileName = fileName;
    }

    public SamlFileResource(@Nonnull String fileName, @Nonnull String data) {
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
        return fileName;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        if (cache.containsKey(fileName)){
            return IOUtils.toInputStream(cache.get(fileName),"UTF-8");
        } else {
            return FileUtils.openInputStream(new File(fileName));
        }
    }

    @Override
    public File getFile() {
        throw new NotImplementedException();
    }

    @Override
    public long contentLength() {
        return new File(fileName).length();
    }

    @Override
    public long lastModified() {
        return new File(fileName).lastModified();
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
        return new ByteArrayOutputStream(){
            @Override
            public void close() throws IOException {
                save(fileName, IOUtils.toString(this.buf, "UTF-8").trim());
            }
        };
    }

    private boolean isNew(String fileName, String data){
        String oldData = cache.containsKey(fileName) ? cache.get(fileName) : "";
        String md5SumNew = org.apache.commons.codec.digest.DigestUtils.md5Hex(data);
        String md5SumOld = org.apache.commons.codec.digest.DigestUtils.md5Hex(oldData);
        return !md5SumNew.equals(md5SumOld);
    }

    private void save(@Nonnull String fileName, @Nonnull String data) throws IOException {
        if(isNew(fileName, data)) {
            FileUtils.writeByteArrayToFile(new File(fileName), data.getBytes("UTF-8"));
            cache.put(fileName, data);
        }
    }
}