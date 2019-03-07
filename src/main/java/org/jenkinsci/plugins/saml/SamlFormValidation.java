package org.jenkinsci.plugins.saml;

import hudson.util.FormValidation;
import org.apache.commons.lang.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;

import static org.jenkinsci.plugins.saml.SamlSecurityRealm.*;

class SamlFormValidation {

    public static FormValidation checkStringFormat(String value) {

        if (StringUtils.isEmpty(value)) {
            return FormValidation.ok();
        }

        if (StringUtils.isBlank(value)) {
            return FormValidation.error(ERROR_ONLY_SPACES_FIELD_VALUE);
        }

        return FormValidation.ok();

    }

    public static FormValidation checkStringAttributeFormat(String value, String message) {

        if (StringUtils.isEmpty(value)) {
            return FormValidation.warning(message);
        }

        if (StringUtils.isBlank(value)) {
            return FormValidation.error(ERROR_ONLY_SPACES_FIELD_VALUE);
        }

        return FormValidation.ok();

    }

    public static FormValidation checkUrlFormat(String url) {
        if (StringUtils.isEmpty(url)) {
            return FormValidation.ok();
        }
        try {
            new URL(url);
        } catch (MalformedURLException e) {
            return FormValidation.error(SamlSecurityRealm.ERROR_MALFORMED_URL, e);
        }
        return FormValidation.ok();
    }

    public static FormValidation checkIntegerFormat(String value) {
        if (StringUtils.isEmpty(value)) {
            return FormValidation.ok();
        }

        long i = 0;
        try {
            i = Long.parseLong(value);
        } catch (NumberFormatException e) {
            return FormValidation.error(ERROR_NOT_VALID_NUMBER, e);
        }

        if (i < 0) {
            return FormValidation.error(ERROR_NOT_VALID_NUMBER);
        }

        if (i > Integer.MAX_VALUE) {
            return FormValidation.error(ERROR_NOT_VALID_NUMBER);
        }

        return FormValidation.ok();
    }

}