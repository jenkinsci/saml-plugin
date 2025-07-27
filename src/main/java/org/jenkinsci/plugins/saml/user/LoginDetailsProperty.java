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

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.SecurityRealm;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.lang.time.FastDateFormat;
import org.jenkinsci.plugins.saml.SamlSecurityRealm;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.core.Authentication;

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

    @SuppressWarnings("unused")
    @DataBoundConstructor
    public LoginDetailsProperty() {
        // NOOP
    }

    @SuppressWarnings("unused")
    public static LoginDetailsProperty currentUserLoginDetails() {
        User user = User.current();
        LoginDetailsProperty loginDetails = null;
        if (user != null && user.getProperty(LoginDetailsProperty.class) != null) {
            loginDetails = user.getProperty(LoginDetailsProperty.class);
        }
        return loginDetails;
    }

    @SuppressWarnings("unused")
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

    @SuppressWarnings("unused")
    public long getLastLoginTimestamp() {
        return lastLoginTimestamp;
    }

    @SuppressWarnings("unused")
    public String getCreateDate() {
        return FastDateFormat.getInstance(ISO_8601).format(new Date(createTimestamp));
    }

    @SuppressWarnings("unused")
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
    public UserProperty reconfigure(StaplerRequest2 req, JSONObject form) {
        return this;
    }

    /**
     * Listen to the login success/failure event to persist {@link LoginDetailsProperty}s properly.
     */
    @SuppressWarnings("unused")
    @Extension
    public static class SecurityListenerImpl extends jenkins.security.SecurityListener {

        @Override
        protected void loggedIn(@edu.umd.cs.findbugs.annotations.NonNull String username) {

            SecurityRealm realm = Jenkins.get().getSecurityRealm();
            if (!(realm instanceof SamlSecurityRealm)) {
                return;
            }

            try {
                User u = User.getById(username, true);
                LoginDetailsProperty o = u.getProperty(LoginDetailsProperty.class);
                if (o == null) {
                    o = new LoginDetailsProperty();
                }
                u.addProperty(o);
                Authentication a = Jenkins.getAuthentication2();
                if (a.getName().equals(username)) {
                    o.update(); // just for defensive sanity checking
                }
            } catch (java.io.IOException e) {
                LOG.log(Level.WARNING, "Failed to record granted authorities", e);
            }
        }
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends UserPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "User Login Properties";
        }

        public LoginDetailsProperty newInstance(User user) {
            return new LoginDetailsProperty();
        }

        @Override
        public boolean isEnabled() {
            return Jenkins.get().getSecurityRealm() instanceof SamlSecurityRealm;
        }
    }
}
