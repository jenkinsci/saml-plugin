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
import hudson.security.GroupDetails;
import jenkins.security.LastGrantedAuthoritiesProperty;
import org.acegisecurity.GrantedAuthority;

import java.util.HashSet;
import java.util.Set;


/**
 * Created by kuisathaverat on 03/05/2017.
 * <p>
 * SAML Group details return the details of a group based on login details of users
 */
public class SamlGroupDetails extends GroupDetails {

    private final String name;
    private final Set<String> members = new HashSet<>();

    public SamlGroupDetails(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getDisplayName() {
        return getName();
    }

    @Override
    public Set<String> getMembers() {
        if (members.isEmpty()) {
            for (User u : User.getAll()) {
                LastGrantedAuthoritiesProperty prop = u.getProperty(LastGrantedAuthoritiesProperty.class);
                if (hasGroupOnAuthorities(prop)) {
                    members.add(u.getId());
                }
            }
        }
        return members;
    }

    private boolean hasGroupOnAuthorities(LastGrantedAuthoritiesProperty prop) {
        if (prop != null) {
            for (GrantedAuthority a : prop.getAuthorities()) {
                if (name.equals(a.getAuthority())) {
                    return true;
                }
            }
        }
        return false;
    }
}
