package org.jenkinsci.plugins.saml;

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_IDP_METADATA_EMPTY;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.ERROR_MALFORMED_URL;
import static org.jenkinsci.plugins.saml.SamlSecurityRealm.NOT_POSSIBLE_TO_GET_THE_METADATA;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.ProxyConfiguration;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import jenkins.model.Jenkins;
import jenkins.util.xml.XMLUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.xml.sax.SAXException;

/**
 * Class to store the info about how to manage the IdP Metadata.
 */
public class IdpMetadataConfiguration extends AbstractDescribableImpl<IdpMetadataConfiguration> {
    private static final Logger LOG = Logger.getLogger(IdpMetadataConfiguration.class.getName());

    /**
     * IdP Metadata on XML format, it implies there are not automatic updates.
     */
    private String xml;

    /**
     * URL to update the IdP Metadata from.
     */
    private String url;
    /**
     * Period in minutes between each IdP Metadata update.
     */
    private final Long period;

    /**
     * Jelly Constructor.
     * @param xml Idp Metadata XML. if xml is null, url and period should not.
     * @param url Url to download the IdP Metadata.
     * @param period Period in minutes between updates of the IdP Metadata.
     */
    @DataBoundConstructor
    public IdpMetadataConfiguration(String xml, String url, Long period) {
        this.xml = xml;
        this.url = url;
        if (StringUtils.isBlank(url) || period == null) {
            this.period = 0L;
        } else {
            this.period = period;
        }
    }

    /**
     * Inline Constructor.
     * @param xml IdP Metadata XML.
     */
    public IdpMetadataConfiguration(@NonNull String xml) {
        this.xml = xml;
        this.period = 0L;
    }

    /**
     * Idp Metadata downloaded from an Url Constructor.
     * @param url URL to grab the IdP Metadata.
     * @param period Period between updates of the IdP Metadata.
     */
    public IdpMetadataConfiguration(@NonNull String url, @NonNull Long period) {
        this.url = url;
        this.period = period;
    }

    public String getXml() {
        return xml;
    }

    public String getUrl() {
        return url;
    }

    public Long getPeriod() {
        return period;
    }

    /**
     * @return Return the Idp Metadata from the XML file JENKINS_HOME/saml-idp.metadata.xml.
     * @throws IOException in case it can not read the IdP Metadata file.
     */
    public String getIdpMetadata() throws IOException {
        return FileUtils.readFileToString(new File(SamlSecurityRealm.getIDPMetadataFilePath()), StandardCharsets.UTF_8);
    }

    /**
     * Creates the IdP Metadata file (saml-idp.metadata.xml) in JENKINS_HOME using the configuration.
     * @throws IOException in case of error writing the file.
     */
    public void createIdPMetadataFile() throws IOException {
        try {
            if (StringUtils.isNotBlank(xml)) {
                Files.write(
                        new File(SamlSecurityRealm.getIDPMetadataFilePath()).toPath(),
                        List.of(xml),
                        StandardCharsets.UTF_8);
            } else {
                updateIdPMetadata();
            }
        } catch (IOException e) {
            throw new IOException("Can not write IdP metadata file in JENKINS_HOME", e);
        }
    }

    /**
     * Gets the IdP Metadata from an URL, then validate it and write it to a file (JENKINS_HOME/saml-idp.metadata.xml).
     * @throws IOException in case of error writing the file or validating the content.
     */
    public void updateIdPMetadata() throws IOException {
        try {
            URLConnection urlConnection = ProxyConfiguration.open(new URL(url));
            try (InputStream in = urlConnection.getInputStream()) {
                StringWriter writer = new StringWriter();
                XMLUtils.safeTransform(new StreamSource(in), new StreamResult(writer));
                String idpXml = writer.toString();

                FormValidation validation = new SamlValidateIdPMetadata(idpXml).get();
                if (FormValidation.Kind.OK == validation.kind) {
                    Files.write(
                            new File(SamlSecurityRealm.getIDPMetadataFilePath()).toPath(),
                            List.of(idpXml),
                            StandardCharsets.UTF_8);
                } else {
                    throw new IllegalArgumentException(validation.getMessage());
                }
            }
        } catch (IOException | TransformerException | SAXException e) {
            throw new IOException("Was not possible to update the IdP Metadata from the URL " + url, e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IdpMetadataConfiguration{");
        if (xml != null) {
            sb.append("xml='…").append(xml.length()).append(" chars…'");
        } else {
            sb.append("xml=null");
        }
        sb.append(", url='").append(url).append('\'');
        sb.append(", period=").append(period);
        sb.append('}');
        return sb.toString();
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends Descriptor<IdpMetadataConfiguration> {
        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends IdpMetadataConfiguration> clazz) {
            super(clazz);
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "";
        }

        @RequirePOST
        public FormValidation doTestIdpMetadata(@QueryParameter("xml") String xml) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (StringUtils.isBlank(xml)) {
                return FormValidation.error(ERROR_IDP_METADATA_EMPTY);
            }

            return new SamlValidateIdPMetadata(xml).get();
        }

        @RequirePOST
        public FormValidation doCheckPeriod(@QueryParameter("period") String period) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkIntegerFormat(period);
        }

        @RequirePOST
        public FormValidation doCheckXml(@QueryParameter("xml") String xml, @QueryParameter("url") String url) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (StringUtils.isBlank(xml) && StringUtils.isBlank(url)) {
                return FormValidation.error(ERROR_IDP_METADATA_EMPTY);
            }

            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doCheckUrl(@QueryParameter("url") String url) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            if (StringUtils.isEmpty(url)) {
                return FormValidation.ok();
            }
            try {
                new URL(url);
            } catch (MalformedURLException e) {
                return FormValidation.error(ERROR_MALFORMED_URL, e);
            }
            return FormValidation.ok();
        }

        @RequirePOST
        public FormValidation doTestIdpMetadataURL(@QueryParameter("url") String url) {
            URLConnection urlConnection;
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            try {
                urlConnection = ProxyConfiguration.open(new URL(url));
            } catch (IOException e) {
                LOG.log(Level.SEVERE, e.getMessage(), e);
                return FormValidation.error(NOT_POSSIBLE_TO_GET_THE_METADATA + url);
            }

            try (InputStream in = urlConnection.getInputStream()) {
                String xml =
                        IOUtils.toString(in, StringUtils.defaultIfEmpty(urlConnection.getContentEncoding(), "UTF-8"));
                return new SamlValidateIdPMetadata(xml).get();
            } catch (MalformedURLException e) {
                return FormValidation.error(ERROR_MALFORMED_URL);
            } catch (IOException e) {
                LOG.log(Level.SEVERE, e.getMessage(), e);
                return FormValidation.error(NOT_POSSIBLE_TO_GET_THE_METADATA + url);
            }
        }
    }
}
