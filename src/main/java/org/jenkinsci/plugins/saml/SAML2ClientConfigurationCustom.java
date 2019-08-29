package org.jenkinsci.plugins.saml;

import org.pac4j.saml.client.SAML2ClientConfiguration;

public class SAML2ClientConfigurationCustom extends SAML2ClientConfiguration {

        private boolean authnRequestSigned = true;

        public SAML2ClientConfigurationCustom() {
        }

        @Override
        public boolean isAuthnRequestSigned() {
            return authnRequestSigned;
        }

        public void setAuthnRequestSigned(boolean authnRequestSigned) {
            this.authnRequestSigned = authnRequestSigned;
            setForceSignRedirectBindingAuthnRequest(authnRequestSigned);
        }
    }