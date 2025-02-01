package org.jenkinsci.plugins.saml;

import hudson.security.SecurityRealm;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Test SamlFileResource implementations with and without cache.
 */
@WithJenkins
class SamlFileResourceTest {

    @TempDir
    private File tempFolder;

    private SamlSecurityRealm samlSecurityRealm;

    @BeforeEach
    void start(JenkinsRule jenkinsRule) {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertThat("The security realm should be saml", securityRealm, instanceOf(SamlSecurityRealm.class));
        samlSecurityRealm = (SamlSecurityRealm) securityRealm;
        Logger logger = Logger.getLogger("org.jenkinsci.plugins.saml");
        logger.setLevel(Level.FINEST);
        LogManager.getLogManager().addLogger(logger);
        Logger logger1 = Logger.getLogger("org.pac4j");
        logger1.setLevel(Level.FINEST);
        LogManager.getLogManager().addLogger(logger1);
    }

    @Test
    @LocalData("configuration")
    void testSamlFileResource() throws InterruptedException, IOException {
        samlSecurityRealm.getAdvancedConfiguration().setUseDiskCache(true);
        File tempFile = File.createTempFile("testSamlFileResource.txt", null, tempFolder);
        SamlFileResource obj = new SamlFileResource(tempFile.getAbsolutePath(), "data");
        long timestamp = obj.lastModified();

        Thread.sleep(1000);
        SamlFileResource obj1 = new SamlFileResource(tempFile.getAbsolutePath(), "data");
        assertEquals(timestamp, obj1.lastModified());

        SamlFileResource obj2 = new SamlFileResource(tempFile.getAbsolutePath(), "data1");
        assertNotEquals(timestamp, obj2.lastModified());
    }

    @Test
    @LocalData("configuration")
    void testGetInputStream() throws IOException {
        assertReadFile();

        samlSecurityRealm.getAdvancedConfiguration().setUseDiskCache(true);
        assertReadFile();
    }

    private void assertReadFile() throws IOException {
        File tempFile = getTempFile("testGetInputStream");
        SamlFileResource obj = new SamlFileResource(tempFile.getAbsolutePath());
        assertEquals("", IOUtils.toString(obj.getInputStream(), UTF_8));
        assertEquals("", FileUtils.readFileToString(tempFile, UTF_8));

        FileUtils.write(new File(tempFile.getAbsolutePath()), "data", UTF_8);
        assertEquals("data", IOUtils.toString(obj.getInputStream(), UTF_8));
        assertEquals("data", FileUtils.readFileToString(tempFile, UTF_8));

        SamlFileResource obj1 = new SamlFileResource(tempFile.getAbsolutePath(), "data1");
        assertEquals("data1", IOUtils.toString(obj1.getInputStream(), UTF_8));
        assertEquals("data1", FileUtils.readFileToString(tempFile, UTF_8));
    }

    private File getTempFile(String filePattern) throws IOException {
        String type;
        if (samlSecurityRealm.getAdvancedConfiguration().getUseDiskCache()) {
            type = "_cache";
        } else {
            type = "_file";
        }
        return File.createTempFile(filePattern + type + ".txt", null, tempFolder);
    }

    @Test
    @LocalData("configuration")
    void testGetOutputStream() throws IOException {
        assertOutputStream();

        samlSecurityRealm.getAdvancedConfiguration().setUseDiskCache(true);
        assertOutputStream();
    }

    private void assertOutputStream() throws IOException {
        File tempFile = getTempFile("testGetOutputStream");
        SamlFileResource obj = new SamlFileResource(tempFile.getAbsolutePath());

        try (OutputStream out = obj.getOutputStream()) {
            IOUtils.write("data", out, UTF_8);
        }
        assertEquals("data", IOUtils.toString(obj.getInputStream(), UTF_8));
        assertEquals("data", FileUtils.readFileToString(tempFile, UTF_8));
    }
}