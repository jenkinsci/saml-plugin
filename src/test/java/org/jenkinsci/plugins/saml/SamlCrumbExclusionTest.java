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

import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Test the ScrumExclusion.
 * @author Ivan Fernandez Calvo
 */
public class SamlCrumbExclusionTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();
    private HttpServletRequest requestOK;
    private HttpServletRequest requestError;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @Before
    public void setup(){
        requestOK = new FakeRequest("/securityRealm/finishLogin");
        requestError = new FakeRequest("/foo/securityRealm/finishLogin");
        response = null;
        filterChain = (servletRequest, servletResponse) -> {
        };
    }

    @LocalData("testReadSimpleConfiguration")
    @Test
    public void testURL() throws ServletException, IOException {
        SamlCrumbExclusion exclusion = new SamlCrumbExclusion();
        assertTrue(exclusion.process(requestOK, response, filterChain));
        assertFalse(exclusion.process(requestError, response, filterChain));
    }

    @Test
    public void testRealmDisabled() throws ServletException, IOException {
        SamlCrumbExclusion exclusion = new SamlCrumbExclusion();
        assertFalse(exclusion.process(requestOK, response, filterChain));
        assertFalse(exclusion.process(requestError, response, filterChain));
    }
}