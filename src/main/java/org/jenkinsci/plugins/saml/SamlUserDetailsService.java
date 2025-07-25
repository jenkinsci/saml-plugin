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

package org.jenkinsci.plugins.saml;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import jenkins.model.Jenkins;
import jenkins.security.LastGrantedAuthoritiesProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * This service is responsible for restoring UserDetails object by userId
 *
 * @see UserDetailsService
 */
public class SamlUserDetailsService implements UserDetailsService {

    public SamlUserDetails loadUserByUsername(@NonNull String username) {

        // try to obtain user details from current authentication details
        Authentication auth = Jenkins.getAuthentication2();
        if (username.compareTo(auth.getName()) == 0 && auth instanceof SamlAuthenticationToken) {
            return (SamlUserDetails) auth.getDetails();
        }

        // try to rebuild authentication details based on data stored in user storage
        User user = User.get(username, false, Collections.emptyMap());
        if (user == null) {
            // User logged in to Jenkins, but it could exist in the backend
            throw new UserMayOrMayNotExistException2(username);
        }

        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);

        if (username.compareTo(user.getId()) == 0) {
            LastGrantedAuthoritiesProperty lastGranted = user.getProperty(LastGrantedAuthoritiesProperty.class);
            if (lastGranted != null) {
                for (GrantedAuthority a : lastGranted.getAuthorities2()) {
                    if (a != SecurityRealm.AUTHENTICATED_AUTHORITY2) {
                        SimpleGrantedAuthority ga = new SimpleGrantedAuthority(a.getAuthority());
                        authorities.add(ga);
                    }
                }
            }
        }
        return new SamlUserDetails(user.getId(), authorities);
    }
}
