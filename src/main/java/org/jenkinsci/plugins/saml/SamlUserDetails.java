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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @see UserDetails
 */
public class SamlUserDetails implements UserDetails {

    private static final long serialVersionUID = 2L;

    private final String username;
    private final Collection<GrantedAuthority> authorities;

    public SamlUserDetails(@NonNull String username, Collection<GrantedAuthority> authorities) {
        this.username = username;
        this.authorities = Collections.unmodifiableCollection(authorities);
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String toString() {
        return "SamlUserDetails{" + "username='" + getUsername() + '\'' + ", authorities="
                + (getAuthorities() == null
                        ? "null"
                        : Arrays.asList(getAuthorities()).toString())
                + '\'' + ", isAccountNonExpired='" + isAccountNonExpired() + '\'' + ", isAccountNonLocked='"
                + isAccountNonLocked() + '\'' + ", isCredentialsNonExpired='" + isCredentialsNonExpired() + '\''
                + ", isEnabled='" + isEnabled() + '}';
    }
}
