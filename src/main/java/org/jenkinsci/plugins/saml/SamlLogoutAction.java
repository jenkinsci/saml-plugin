/*
 * The MIT License
 *
 * Copyright (c) 2016 CloudBees, Inc., James Nord
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.saml;

import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import hudson.Extension;
import hudson.model.UnprotectedRootAction;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;

/**
 * A page that shows a simple message when the user logs out.
 * This prevents a logout - login loop when using this security realm and Anonymous does not have {@code Overall.READ} permission.
 */
@Extension
public class SamlLogoutAction implements UnprotectedRootAction {

    /**
     * The URL of the action.
     */
    static final String POST_LOGOUT_URL = "samlLogout";

    @Override
    public String getDisplayName() {
        return "SAML Logout";
    }

    @Override
    public String getIconFileName() {
        // hide it
        return null;
    }

    @Override
    public String getUrlName() {
        return POST_LOGOUT_URL;
    }

    @Restricted(NoExternalUse.class) // jelly only
    public String getSamlURL() {
        SecurityRealm r = Jenkins.getActiveInstance().getSecurityRealm();
        if (r instanceof SamlSecurityRealm) {
            SamlSecurityRealm smlsr = (SamlSecurityRealm) r;
            return smlsr.getIdpMetadata();
        }
        // only called from the Jelly if the SamlSecurityRealm is set...
        return "";
    }

}