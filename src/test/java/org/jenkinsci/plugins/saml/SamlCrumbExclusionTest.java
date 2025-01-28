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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test the ScrumExclusion.
 *
 * @author Ivan Fernandez Calvo
 */
@WithJenkins
class SamlCrumbExclusionTest {

    private HttpServletRequest requestOK;
    private HttpServletRequest requestError;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setup() {
        requestOK = new FakeRequest("/securityRealm/finishLogin");
        requestError = new FakeRequest("/foo/securityRealm/finishLogin");
        response = null;
        filterChain = (servletRequest, servletResponse) -> {
        };
    }

    @LocalData("testReadSimpleConfiguration")
    @Test
    void testURL(JenkinsRule jenkinsRule) throws ServletException, IOException {
        SamlCrumbExclusion exclusion = new SamlCrumbExclusion();
        assertTrue(exclusion.process(requestOK, response, filterChain));
        assertFalse(exclusion.process(requestError, response, filterChain));
    }

    @Test
    void testRealmDisabled(JenkinsRule jenkinsRule) throws ServletException, IOException {
        SamlCrumbExclusion exclusion = new SamlCrumbExclusion();
        assertFalse(exclusion.process(requestOK, response, filterChain));
        assertFalse(exclusion.process(requestError, response, filterChain));
    }
}