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
import org.pac4j.core.io.WritableResource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

class RewriteableStringResource implements WritableResource {

  private static final Logger LOG = Logger.getLogger(RewriteableStringResource.class.getName());

  private final String name;

  private byte[] string;

  public RewriteableStringResource(String string, String name) {
    try {
      //FIXME [kuisatahverat] assume UTF-8 file, it could not be UTF-8, string.getBytes() uses the platform encoding maybe is better.
      this.string = string != null ? string.getBytes("UTF-8") : null;
    } catch (UnsupportedEncodingException e) {
      LOG.log(Level.SEVERE, "Could not get string bytes.", e);
    }
    this.name = name;
  }

  public RewriteableStringResource(String string) {
    this(string, "");
  }

  public RewriteableStringResource() {
    this(null, "");
  }

  @Override
  public boolean exists() {
    return string != null;
  }

  @Override
  public String getFilename() {
    return name;
  }

  @Override
  public java.io.InputStream getInputStream() throws IOException {
    if (string == null) {
      throw new IOException("no data");
    }
    return new ByteArrayInputStream(string);
  }

  @Override
  public File getFile() {
    try {
      File temp = File.createTempFile("jenkins-saml-",".bin");
      FileUtils.writeByteArrayToFile(temp, string);
    } catch (IOException e) {
      LOG.log(Level.SEVERE,"Is not possible to create a temp file",e);
    }
    return null;
  }

  @Override
  public OutputStream getOutputStream() throws IOException {
    return new ByteArrayOutputStream() {
      @Override
      public void close() throws IOException {
        super.close();
        string = toByteArray();
      }
    };
  }
}
