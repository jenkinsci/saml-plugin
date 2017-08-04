/* Licensed to Jenkins CI under one or more contributor license
agreements.  See the NOTICE file distributed with this work
for additional information regarding copyright ownership.
Jenkins CI licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.  You may obtain a copy of the
License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License. */
package org.jenkinsci.plugins.saml.user;

import hudson.Extension;
import hudson.model.Descriptor.FormException;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import net.sf.json.JSONObject;
import org.acegisecurity.GrantedAuthority;
import org.apache.commons.lang.time.FastDateFormat;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.saml.SamlSecurityRealm;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Store details about create and login processes
 *
 * @author Kuisathaverat
 */
public class LoginDetailsProperty extends UserProperty {
    private static final Logger LOG = Logger.getLogger(LoginDetailsProperty.class.getName());
    private static final String ISO_8601 = "yyyy-MM-dd'T'HH:mm:ssZ";
    private long createTimestamp;
    private long lastLoginTimestamp;
    private long loginCount;


    @DataBoundConstructor
    public LoginDetailsProperty() {
    }

    public static LoginDetailsProperty currentUserLoginDetails() {
        User user = User.current();
        LoginDetailsProperty loginDetails = null;
        if (user != null && user.getProperty(LoginDetailsProperty.class) != null) {
            loginDetails = user.getProperty(LoginDetailsProperty.class);
        }
        return loginDetails;
    }

    public static void currentUserSetLoginDetails() {
        User user = User.current();
        if (user != null && user.getProperty(LoginDetailsProperty.class) != null) {
            LoginDetailsProperty loginDetails = user.getProperty(LoginDetailsProperty.class);
            loginDetails.update();
        }
    }

    public void update() {
        long now = System.currentTimeMillis();
        if (getCreateTimestamp() == 0) {
            setCreateTimestamp(now);
        }

        setLastLoginTimestamp(now);
        setLoginCount(getLoginCount() + 1);
        try {
            user.save();
        } catch (java.io.IOException e) {
            LOG.log(Level.WARNING, e.getMessage(), e);
        }
    }

    public long getCreateTimestamp() {
        return createTimestamp;
    }

    public long getLastLoginTimestamp() {
        return lastLoginTimestamp;
    }

    public String getCreateDate() {
        return FastDateFormat.getInstance(ISO_8601).format(new Date(createTimestamp));
    }

    public String getLastLoginDate() {
        return FastDateFormat.getInstance(ISO_8601).format(new Date(lastLoginTimestamp));
    }

    public long getLoginCount() {
        return loginCount;
    }

    public void setCreateTimestamp(long createTimestamp) {
        this.createTimestamp = createTimestamp;
    }

    public void setLastLoginTimestamp(long lastLoginTimestamp) {
        this.lastLoginTimestamp = lastLoginTimestamp;
    }

    public void setLoginCount(long loginCount) {
        this.loginCount = loginCount;
    }

    @Override
    public UserProperty reconfigure(StaplerRequest req, JSONObject form) throws FormException {
        return this;
    }


    /**
     * Listen to the login success/failure event to persist {@link GrantedAuthority}s properly.
     */
    @Extension
    public static class SecurityListenerImpl extends jenkins.security.SecurityListener {
        @Override
        protected void authenticated(@javax.annotation.Nonnull org.acegisecurity.userdetails.UserDetails details) {
            //NOOP
        }

        @Override
        protected void failedToAuthenticate(@javax.annotation.Nonnull String username) {
            //NOOP
        }

        @Override
        protected void loggedIn(@javax.annotation.Nonnull String username) {
            SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();
            if (!(realm instanceof SamlSecurityRealm)) {
                return;
            }

            try {
                User u = User.get(username);
                LoginDetailsProperty o = u.getProperty(LoginDetailsProperty.class);
                if (o == null)
                    u.addProperty(o = new LoginDetailsProperty());
                org.acegisecurity.Authentication a = Jenkins.getAuthentication();
                if (a != null && a.getName().equals(username))
                    o.update();    // just for defensive sanity checking
            } catch (java.io.IOException e) {
                LOG.log(Level.WARNING, "Failed to record granted authorities", e);
            }
        }

        @Override
        protected void failedToLogIn(@javax.annotation.Nonnull String username) {
            //NOOP
        }

        @Override
        protected void loggedOut(@javax.annotation.Nonnull String username) {
            //NOOP
        }
    }


    @Extension
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        public String getDisplayName() {
            return "User Login Properties";
        }

        public LoginDetailsProperty newInstance(User user) {
            return new LoginDetailsProperty();
        }

    }
}
