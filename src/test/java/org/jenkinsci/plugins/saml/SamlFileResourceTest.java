package org.jenkinsci.plugins.saml;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class SamlFileResourceTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void testSamlFileResource() throws InterruptedException, IOException {
        File tempFile = tempFolder.newFile("testSamlFileResource.txt");
        SamlFileResource obj = new SamlFileResource(tempFile.getAbsolutePath(), "data");
        long timestamp = obj.lastModified();
        Thread.sleep(1000);
        SamlFileResource obj1 = new SamlFileResource(tempFile.getAbsolutePath(), "data");
        assertEquals(timestamp, obj1.lastModified());

        SamlFileResource obj2 = new SamlFileResource(tempFile.getAbsolutePath(), "data1");
        assertNotEquals(timestamp, obj2.lastModified());
    }

    @Test
    public void testGetInputStream() throws IOException {
        File tempFile = tempFolder.newFile("testGetInputStream.txt");
        SamlFileResource obj = new SamlFileResource(tempFile.getAbsolutePath());
        assertEquals("",IOUtils.toString(obj.getInputStream(),"UTF-8"));
        assertEquals("",FileUtils.readFileToString(tempFile,"UTF-8"));

        FileUtils.write(new File(tempFile.getAbsolutePath()), "data", "UTF-8");
        assertEquals("data",IOUtils.toString(obj.getInputStream(),"UTF-8"));
        assertEquals("data",FileUtils.readFileToString(tempFile,"UTF-8"));

        SamlFileResource obj1 = new SamlFileResource(tempFile.getAbsolutePath(), "data1");
        assertEquals("data1",IOUtils.toString(obj.getInputStream(),"UTF-8"));
        assertEquals("data1",FileUtils.readFileToString(tempFile,"UTF-8"));
    }

    @Test
    public void testGetOutputStream() throws IOException {
        File tempFile = tempFolder.newFile("testGetOutputStream.txt");
        SamlFileResource obj = new SamlFileResource(tempFile.getAbsolutePath());
        try(OutputStream out = obj.getOutputStream()){
            IOUtils.write("data", out, "UTF-8");
        }
        assertEquals("data",IOUtils.toString(obj.getInputStream(),"UTF-8"));
        assertEquals("data",FileUtils.readFileToString(tempFile,"UTF-8"));
    }
}