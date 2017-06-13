package org.jenkinsci.plugins.saml;

import java.io.*;

class RewriteableStringResource implements org.pac4j.core.io.WritableResource {

  private final String name;

  private byte[] string;

  public RewriteableStringResource(String string, String name) {
    this.string = string != null ? string.getBytes() : null;
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
  public InputStream getInputStream() throws IOException {
    if (string == null) {
      throw new IOException("no data");
    }
    return new ByteArrayInputStream(string);
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
