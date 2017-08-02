package org.jenkinsci.plugins.saml;

import hudson.util.FormValidation;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.apache.commons.io.IOUtils;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.pac4j.saml.util.Configuration;

import java.io.IOException;

public class SamlValidateIdPMetadata extends OpenSAMLWrapper<FormValidation>{

    private final String idpMetadata;

    public SamlValidateIdPMetadata(String idpMetadata){
        this.idpMetadata = idpMetadata;
    }

    @Override
    protected FormValidation process() {
        try (final java.io.InputStream in = IOUtils.toInputStream(idpMetadata, "UTF-8")) {
            final org.w3c.dom.Document inCommonMDDoc = Configuration.getParserPool().parse(in);
            final org.w3c.dom.Element metadataRoot = inCommonMDDoc.getDocumentElement();
            DOMMetadataResolver idpMetadataProvider = new DOMMetadataResolver(metadataRoot);
            idpMetadataProvider.setParserPool(Configuration.getParserPool());
            idpMetadataProvider.setFailFastInitialization(true);
            idpMetadataProvider.setRequireValidMetadata(true);
            idpMetadataProvider.setId(idpMetadataProvider.getClass().getCanonicalName());
            idpMetadataProvider.initialize();
        } catch (IOException e) {
            return FormValidation.error("The IdP Metadata not valid.", e);
        } catch (XMLParserException e) {
            return FormValidation.error("The IdP Metadata not valid XML.", e);
        } catch (ComponentInitializationException e) {
            return FormValidation.error("The IdP Metadata not valid content.", e);
        }
        return FormValidation.ok("Success");
    }
}
