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

import hudson.model.User;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import jenkins.security.LastGrantedAuthoritiesProperty;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This service is responsible for restoring UserDetails object by userId
 *
 * @see UserDetailsService
 */
public class SamlUserDetailsService implements UserDetailsService {

    public SamlUserDetails loadUserByUsername(@Nonnull String username) throws UsernameNotFoundException, DataAccessException {

        // try to obtain user details from current authentication details
        Authentication auth = Jenkins.getAuthentication();
        if (auth != null && username.compareTo(auth.getName()) == 0 && auth instanceof SamlAuthenticationToken) {
            return (SamlUserDetails) auth.getDetails();
        }

        // try to rebuild authentication details based on data stored in user storage
        User user = User.get(username, false, Collections.emptyMap());
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

        if (username.compareTo(user.getId()) == 0) {
            LastGrantedAuthoritiesProperty lastGranted = user.getProperty(LastGrantedAuthoritiesProperty.class);
            if (lastGranted != null) {
                for (GrantedAuthority a : lastGranted.getAuthorities()) {
                    if (a != SecurityRealm.AUTHENTICATED_AUTHORITY) {
                        SamlGroupAuthority ga = new SamlGroupAuthority(a.getAuthority());
                        authorities.add(ga);
                    }
                }
            }
        }

        SamlUserDetails userDetails = new SamlUserDetails(user.getId(), authorities.toArray(new GrantedAuthority[0]));
        return userDetails;
    }
}
