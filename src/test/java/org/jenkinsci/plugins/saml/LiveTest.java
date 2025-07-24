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

import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assume.assumeTrue;

import hudson.model.Descriptor;
import hudson.util.Secret;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.htmlunit.Page;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlPasswordInput;
import org.htmlunit.html.HtmlTextInput;
import org.jenkinsci.plugins.saml.properties.DataBindingMethod;
import org.jenkinsci.plugins.saml.properties.SpEntityId;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.RealJenkinsRule;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;

public class LiveTest {

    @BeforeClass
    public static void requiresDocker() {
        assumeTrue(DockerClientFactory.instance().isDockerAvailable());
    }

    @Rule
    public final RealJenkinsRule rr = new RealJenkinsRule();

    @SuppressWarnings("rawtypes")
    private final GenericContainer samlContainer =
            new GenericContainer("kristophjunge/test-saml-idp:1.14.15").withExposedPorts(80);

    @After
    public void stop() {
        samlContainer.stop();
    }

    private static final String SERVICE_PROVIDER_ID = "jenkins-dev";

    @Test
    public void authenticationOK() throws Throwable {
        then(() -> new AuthenticationOK(readIdPMetadataFromURL()));
    }

    private static class AuthenticationOK implements RealJenkinsRule.Step {
        private final String idpMetadata;

        AuthenticationOK(String idpMetadata) {
            this.idpMetadata = idpMetadata;
        }

        @Override
        public void run(JenkinsRule r) throws Throwable {
            SamlSecurityRealm realm = configureBasicSettings(new IdpMetadataConfiguration(idpMetadata));
            r.jenkins.setSecurityRealm(realm);
            configureAuthorization();
            makeLoginWithUser1(r);
        }
    }

    @Test
    public void authenticationRelayState() throws Throwable {
        rr.withLogger("org.jenkinsci.plugins.saml.RefererStateGenerator", Level.FINE);
        then(() -> new AuthenticationRelayStateRandom(readIdPMetadataFromURL()));
    }

    private static class AuthenticationRelayStateRandom implements RealJenkinsRule.Step {
        private final String idpMetadata;

        AuthenticationRelayStateRandom(String idpMetadata) {
            this.idpMetadata = idpMetadata;
        }

        @Override
        public void run(JenkinsRule r) throws Throwable {
            IdpMetadataConfiguration idpMetadataConfiguration = new IdpMetadataConfiguration(idpMetadata);
            SamlSecurityRealm realm = configureBasicSettings(idpMetadataConfiguration);
            r.jenkins.setSecurityRealm(realm);
            configureAuthorization();
            final HtmlPage htmlPage = makeLoginWithUser1(r, "/builds");
            assertThat(htmlPage.getUrl().toString(), endsWith("/builds"));
            Jenkins.logRecords.stream()
                    .filter(l -> l.getLoggerName().equals("org.jenkinsci.plugins.saml.RefererStateGenerator"))
                    .forEach(l -> assertThat(l.getMessage(), containsString("Safe URL redirection: /builds")));
        }
    }

    @Test
    public void authenticationOKFromURL() throws Throwable {
        then(() -> new AuthenticationOKFromURL(createIdPMetadataURL()));
    }

    private static class AuthenticationOKFromURL implements RealJenkinsRule.Step {
        private final String idpMetadataUrl;

        AuthenticationOKFromURL(String idpMetadataUrl) {
            this.idpMetadataUrl = idpMetadataUrl;
        }

        @Override
        public void run(JenkinsRule r) throws Throwable {
            SamlSecurityRealm realm = configureBasicSettings(new IdpMetadataConfiguration(idpMetadataUrl, 0L));
            Jenkins.XSTREAM2.toXMLUTF8(realm, System.out);
            System.out.println();
            r.jenkins.setSecurityRealm(realm);
            configureAuthorization();
            makeLoginWithUser1(r);
        }
    }

    @Test
    public void authenticationOKPostBinding() throws Throwable {
        then(() -> new AuthenticationOKPostBinding(readIdPMetadataFromURL()));
    }

    private static class AuthenticationOKPostBinding implements RealJenkinsRule.Step {
        private final String idpMetadata;

        AuthenticationOKPostBinding(String idpMetadata) {
            this.idpMetadata = idpMetadata;
        }

        @Override
        public void run(JenkinsRule r) throws Throwable {
            SamlSecurityRealm realm = configureBasicSettings(new IdpMetadataConfiguration(idpMetadata));
            realm.getProperties().add(new DataBindingMethod(DataBindingMethod.HTTP_POST_BINDING));
            r.jenkins.setSecurityRealm(realm);
            configureAuthorization();
            makeLoginWithUser1(r);
        }
    }

    @Test
    public void authenticationFail() throws Throwable {
        then(() -> new AuthenticationFail(readIdPMetadataFromURL()));
    }

    private static class AuthenticationFail implements RealJenkinsRule.Step {
        private final String idpMetadata;

        AuthenticationFail(String idpMetadata) {
            this.idpMetadata = idpMetadata;
        }

        @Override
        public void run(JenkinsRule r) throws Throwable {
            SamlSecurityRealm realm = configureBasicSettings(new IdpMetadataConfiguration(idpMetadata));
            r.jenkins.setSecurityRealm(realm);
            configureAuthorization();
            JenkinsRule.WebClient wc = r.createWebClient();
            HtmlPage login = openLogin(wc, r);
            ((HtmlTextInput) login.getElementById("username")).setText("user1");
            ((HtmlPasswordInput) login.getElementById("password")).setText("WrOnGpAsSwOrD");
            HtmlPage fail = login.getElementsByTagName("button").get(0).click();
            assertThat(
                    fail.getWebResponse().getContentAsString(),
                    containsString(
                            "Either no user with the given username could be found, or the password you gave was wrong"));
            assertThat(fail.getUrl().toString(), containsString("simplesaml/module.php/core/loginuserpass.php"));
        }
    }

    private String readIdPMetadataFromURL() throws IOException {
        // get saml metadata from IdP
        URL metadata = new URL(createIdPMetadataURL());
        URLConnection connection = metadata.openConnection();
        return IOUtils.toString(connection.getInputStream(), StandardCharsets.UTF_8);
    }

    private String createIdPMetadataURL() {
        return "http://" + samlContainer.getHost() + ":" + samlContainer.getFirstMappedPort()
                + "/simplesaml/saml2/idp/metadata.php";
    }

    @FunctionalInterface
    private interface SupplierWithIO<T> {
        T get() throws IOException;
    }

    private void then(SupplierWithIO<RealJenkinsRule.Step> provider) throws Throwable {
        rr.startJenkins();
        try {
            startSimpleSAML(rr.getUrl().toString());
            rr.runRemotely(provider.get());
        } finally {
            rr.stopJenkins();
        }
    }

    private static void configureAuthorization() {
        Jenkins.get()
                .setAuthorizationStrategy(new MockAuthorizationStrategy()
                        .grant(Jenkins.ADMINISTER)
                        .everywhere()
                        .to("group1")
                        .grant(Jenkins.READ)
                        .everywhere()
                        .to("group2"));
    }

    private static SamlSecurityRealm configureBasicSettings(IdpMetadataConfiguration idpMetadataConfiguration)
            throws IOException, Descriptor.FormException {
        // TODO use @DataBoundSetter wherever possible and load defaults from DescriptorImpl
        File samlKey = new File(Jenkins.get().getRootDir(), "saml-key.jks");
        FileUtils.copyURLToFile(Objects.requireNonNull(LiveTest.class.getResource("LiveTest/saml-key.jks")), samlKey);
        SamlEncryptionData samlEncryptionData = new SamlEncryptionData(
                samlKey.getAbsolutePath(),
                Secret.fromString("changeit"),
                Secret.fromString("changeit"),
                null,
                false,
                true);
        var samlSecurityRealm = new SamlSecurityRealm(
                idpMetadataConfiguration,
                "displayName",
                "eduPersonAffiliation",
                "uid",
                "email",
                null,
                "none",
                List.of());
        samlSecurityRealm.getProperties().add(samlEncryptionData);
        samlSecurityRealm.getProperties().add(new SpEntityId(SERVICE_PROVIDER_ID));
        return samlSecurityRealm;
    }

    private void startSimpleSAML(String rootUrl) {
        samlContainer
                .withEnv("SIMPLESAMLPHP_SP_ENTITY_ID", SERVICE_PROVIDER_ID)
                .withEnv("SIMPLESAMLPHP_SP_ASSERTION_CONSUMER_SERVICE", rootUrl + "securityRealm/finishLogin")
                . // login back URL
                withEnv("SIMPLESAMLPHP_SP_SINGLE_LOGOUT_SERVICE", rootUrl + "logout"); // unused
        System.out.println(samlContainer.getEnv());
        samlContainer.start();
        samlContainer.copyFileToContainer(
                MountableFile.forClasspathResource("org/jenkinsci/plugins/saml/LiveTest/users.php"),
                "/var/www/simplesamlphp/config/authsources.php"); // users info
        samlContainer.copyFileToContainer(
                MountableFile.forClasspathResource("org/jenkinsci/plugins/saml/LiveTest/config.php"),
                "/var/www/simplesamlphp/config/config.php"); // config info,
        samlContainer.copyFileToContainer(
                MountableFile.forClasspathResource("org/jenkinsci/plugins/saml/LiveTest/saml20-idp-hosted.php"),
                "/var/www/simplesamlphp/metadata/saml20-idp-hosted.php"); // IdP advanced configuration
    }

    private static HtmlPage openLogin(JenkinsRule.WebClient wc, JenkinsRule r) throws Exception {
        return openLogin(wc, r, null);
    }

    private static HtmlPage openLogin(JenkinsRule.WebClient wc, JenkinsRule r, String startUrl) throws Exception {
        wc.setThrowExceptionOnFailingStatusCode(false);
        String loc = r.getURL().toString();
        if (startUrl != null) {
            loc += startUrl;
        }
        // in default redirectEnabled mode, this gets a 403 from Jenkins, perhaps because the redirect to
        // /securityRealm/commenceLogin is via JavaScript not a 302
        while (true) {
            @SuppressWarnings("deprecation")
            Page p = wc.getPage(loc);
            int code = p.getWebResponse().getStatusCode();
            switch (code) {
                case 302:
                case 303:
                    loc = p.getWebResponse().getResponseHeaderValue("Location");
                    System.out.println("redirecting to " + loc);
                    break;
                case 200:
                    wc.setRedirectEnabled(true);
                    wc.setThrowExceptionOnFailingStatusCode(true);
                    assertThat(
                            p.getWebResponse().getContentAsString(),
                            containsString("Enter your username and password")); // SAML service login page
                    return (HtmlPage) p;
                default:
                    assert false : code;
            }
        }
    }

    private static void makeLoginWithUser1(JenkinsRule r) throws Exception {
        makeLoginWithUser1(r, null);
    }

    private static HtmlPage makeLoginWithUser1(JenkinsRule r, String from) throws Exception {
        JenkinsRule.WebClient wc = r.createWebClient();
        HtmlPage login = openLogin(wc, r, from);
        ((HtmlTextInput) login.getElementById("username")).setText("user1");
        ((HtmlPasswordInput) login.getElementById("password")).setText("user1pass");
        HtmlPage dashboard = login.getElementsByTagName("button").get(0).click();
        assertThat(
                dashboard.getWebResponse().getContentAsString(),
                allOf(containsString("User 1"), containsString("Manage Jenkins")));
        return dashboard;
    }
}
