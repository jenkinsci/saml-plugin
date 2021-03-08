/*
 * Copyright 2021 CloudBees, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jenkinsci.plugins.saml;

import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import hudson.util.Secret;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import jenkins.model.Jenkins;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

public class LiveTest {

    @Rule public RealJenkinsRule rr = new RealJenkinsRule();

    @SuppressWarnings("rawtypes")
    private GenericContainer samlContainer = new GenericContainer("kristophjunge/test-saml-idp:1.14.15").withExposedPorts(80);

    @After public void stop() {
        samlContainer.stop();
    }

    public static final String SAML2_REDIRECT_BINDING_URI = "HTTP-Redirect";
    public static final String SAML2_POST_BINDING_URI = "HTTP-POST";

    private static final String SERVICE_PROVIDER_ID = "jenkins-dev";

    @Test
    public void authenticationOK() throws Throwable {
        startSimpleSAML(rr.getUrl().toString());
        String idpMetadata = readIdPMetadataFromURL();

        rr.then(new AuthenticationOK(idpMetadata));
    }
    private static class AuthenticationOK implements RealJenkinsRule.Step {
        private final String idpMetadata;
        AuthenticationOK(String idpMetadata) {
            this.idpMetadata = idpMetadata;
        }
        @Override
        public void run(JenkinsRule r) throws Throwable {
            // Authentication
            SamlSecurityRealm realm = configureBasicSettings(new IdpMetadataConfiguration(idpMetadata), new SamlAdvancedConfiguration(false, null, SERVICE_PROVIDER_ID, null, /* TODO maximumSessionLifetime unused */null));
            Jenkins.XSTREAM2.toXMLUTF8(realm, System.out);
            System.out.println();
            r.jenkins.setSecurityRealm(realm);

            configureAuthorization();

            makeLoginWithUser1(r);
        }
    }

    /*
    @Test
    public void authenticationOKFromURL() throws IOException, InterruptedException {
        jenkins.open(); // navigate to root
        String rootUrl = jenkins.getCurrentUrl();
        SAMLContainer samlServer = startSimpleSAML(rootUrl);

        GlobalSecurityConfig sc = new GlobalSecurityConfig(jenkins);
        sc.open();

        // Authentication
        SamlSecurityRealm realm = configureBasicSettings(sc);
        realm.setUrl(createIdPMetadataURL(samlServer));

        configureEncrytion(realm);
        configureAuthorization(sc);

        waitFor().withTimeout(10, TimeUnit.SECONDS).until(() -> hasContent("Enter your username and password")); // SAML service login page

        // SAML server login
        makeLoginWithUser1();
    }

    @Test
    public void authenticationOKPostBinding() throws IOException, InterruptedException {
        jenkins.open(); // navigate to root
        String rootUrl = jenkins.getCurrentUrl();
        SAMLContainer samlServer = startSimpleSAML(rootUrl);

        GlobalSecurityConfig sc = new GlobalSecurityConfig(jenkins);
        sc.open();

        // Authentication
        SamlSecurityRealm realm = configureBasicSettings(sc);
        String idpMetadata = readIdPMetadataFromURL(samlServer);
        realm.setXml(idpMetadata);
        realm.setBinding(SAML2_POST_BINDING_URI);
        configureEncrytion(realm);
        configureAuthorization(sc);

        waitFor().withTimeout(10, TimeUnit.SECONDS).until(() -> hasContent("Enter your username and password")); // SAML service login page

        // SAML server login
        makeLoginWithUser1();
    }

    @Test
    public void authenticationFail() throws IOException, InterruptedException {
        jenkins.open(); // navigate to root
        String rootUrl = jenkins.getCurrentUrl();
        SAMLContainer samlServer = startSimpleSAML(rootUrl);

        GlobalSecurityConfig sc = new GlobalSecurityConfig(jenkins);
        sc.open();

        // Authentication
        SamlSecurityRealm realm = configureBasicSettings(sc);
        String idpMetadata = readIdPMetadataFromURL(samlServer);
        realm.setXml(idpMetadata);

        configureEncrytion(realm);
        configureAuthorization(sc);

        waitFor().withTimeout(10, TimeUnit.SECONDS).until(() -> hasContent("Enter your username and password")); // SAML service login page

        // SAML server login
        find(by.id("username")).sendKeys("user1");
        find(by.id("password")).sendKeys("WrOnGpAsSwOrD");
        find(by.button("Login")).click();

        waitFor().withTimeout(5, TimeUnit.SECONDS).until(() -> hasContent("Either no user with the given username could be found, or the password you gave was wrong").matchesSafely(driver)); // wait for the login to propagate
        assertThat(jenkins.getCurrentUrl(), containsString("simplesaml/module.php/core/loginuserpass.php"));
    }
    */

    private String readIdPMetadataFromURL() throws IOException {
        // get saml metadata from IdP
        URL metadata = new URL(createIdPMetadataURL());
        URLConnection connection = metadata.openConnection();
        return IOUtils.toString(connection.getInputStream(), StandardCharsets.UTF_8);
    }

    private String createIdPMetadataURL() {
        return "http://" + samlContainer.getHost() + ":" + samlContainer.getFirstMappedPort() + "/simplesaml/saml2/idp/metadata.php";
    }

    private static void configureAuthorization() {
        Jenkins.get().setAuthorizationStrategy(new MockAuthorizationStrategy().
                grant(Jenkins.ADMINISTER).everywhere().to("group1").
                grant(Jenkins.READ).everywhere().to("group2"));
    }

    private static SamlSecurityRealm configureBasicSettings(IdpMetadataConfiguration idpMetadataConfiguration, SamlAdvancedConfiguration advancedConfiguration) throws IOException {
        // TODO use @DataBoundSetter wherever possible and load defaults from DescriptorImpl
        File samlKey = new File(Jenkins.get().getRootDir(), "saml-key.jks");
        FileUtils.copyURLToFile(LiveTest.class.getResource("LiveTest/saml-key.jks"), samlKey);
        SamlEncryptionData samlEncryptionData = new SamlEncryptionData(samlKey.getAbsolutePath(), Secret.fromString("changeit"), Secret.fromString("changeit"), null, false);
        return new SamlSecurityRealm(idpMetadataConfiguration, "displayName", "eduPersonAffiliation", 86400, "uid", "email", null, advancedConfiguration, samlEncryptionData, "none", SAML2_REDIRECT_BINDING_URI, Collections.emptyList());
    }

    private void startSimpleSAML(String rootUrl) throws IOException, InterruptedException {
        samlContainer.
                withEnv("SIMPLESAMLPHP_SP_ENTITY_ID", SERVICE_PROVIDER_ID).
                withEnv("SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE", rootUrl + "securityRealm/finishLogin"). // login back URL
                withEnv("SIMPLESAMLPHP_SP_SINGLE_LOGOUT_SERVICE", rootUrl + "logout"); // unused
        samlContainer.start();
        samlContainer.copyFileToContainer(MountableFile.forClasspathResource("org/jenkinsci/plugins/saml/LiveTest/users.php"), "/var/www/simplesamlphp/config/authsources.php"); // users info
        samlContainer.copyFileToContainer(MountableFile.forClasspathResource("org/jenkinsci/plugins/saml/LiveTest/config.php"), "/var/www/simplesamlphp/config/config.php"); // config info,
        samlContainer.copyFileToContainer(MountableFile.forClasspathResource("org/jenkinsci/plugins/saml/LiveTest/saml20-idp-hosted.php"), "/var/www/simplesamlphp/metadata/saml20-idp-hosted.php"); //IdP advanced configuration
    }

    private static void makeLoginWithUser1(JenkinsRule r) throws Exception {
        // TODO commenceLogin fails with: SAMLException: Identity provider has no single sign on service available for the selected profileHTTP-Redirect
        // https://github.com/jenkinsci/saml-plugin/blob/master/doc/TROUBLESHOOTING.md#samlexception-identity-provider-has-no-single-sign-on-service-available-for-the-selected
        HtmlPage login = r.createWebClient().goTo("");
        assertThat(login.getWebResponse().getContentAsString(), containsString("Enter your username and password")); // SAML service login page
        ((HtmlTextInput) login.getElementById("username")).setText("user1");
        ((HtmlTextInput) login.getElementById("password")).setText("user1pass");
        HtmlPage dashboard = ((HtmlButton) login.getElementByName("Login")).click();
        assertThat(dashboard.getWebResponse().getContentAsString(), allOf(containsString("User 1"), containsString("Manage Jenkins")));
    }

}
