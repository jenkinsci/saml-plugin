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

import com.google.common.base.Preconditions;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.kohsuke.stapler.*;
import org.opensaml.common.xml.SAMLConstants;
import org.pac4j.core.client.RedirectAction;
import org.pac4j.core.client.RedirectAction.RedirectType;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.J2ERequestContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.RequiresHttpAction;
import org.pac4j.saml.client.Saml2Client;
import org.pac4j.saml.credentials.Saml2Credentials;
import org.pac4j.saml.profile.Saml2Profile;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Authenticates the user via SAML.
 * This class is the main entry point to the plugin.
 * Uses Stapler (stapler.kohsuke.org) to bind methods to URLs.
 *
 * @see SecurityRealm
 */
public class SamlSecurityRealm extends SecurityRealm {
  /**
   * URL to process the SAML answers
   */
  public static final String CONSUMER_SERVICE_URL_PATH = "securityRealm/finishLogin";


  private static final Logger LOG = Logger.getLogger(SamlSecurityRealm.class.getName());
  private static final String REFERER_ATTRIBUTE = SamlSecurityRealm.class.getName() + ".referer";
  private static final String DEFAULT_DISPLAY_NAME_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
  private static final String DEFAULT_GROUPS_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/claims/Group";
  private static final int DEFAULT_MAXIMUM_AUTHENTICATION_LIFETIME = 24 * 60 * 60; // 24h
  private static final String DEFAULT_USERNAME_CASE_CONVERSION = "none";

  private String idpMetadata;
  private String displayNameAttributeName;
  private String groupsAttributeName;
  private int maximumAuthenticationLifetime;
  private String usernameCaseConversion;

  private String usernameAttributeName;

  private SamlEncryptionData encryptionData = null;

  /**
   * Jenkins passes these parameters in when you update the settings.
   * It does this because of the @DataBoundConstructor
   */
  @DataBoundConstructor
  public SamlSecurityRealm(String signOnUrl, String idpMetadata, String displayNameAttributeName, String groupsAttributeName, Integer maximumAuthenticationLifetime, String usernameAttributeName, SamlEncryptionData encryptionData, String usernameCaseConversion) {
    super();
    this.idpMetadata = Util.fixEmptyAndTrim(idpMetadata);
    this.displayNameAttributeName = DEFAULT_DISPLAY_NAME_ATTRIBUTE_NAME;
    this.groupsAttributeName = DEFAULT_GROUPS_ATTRIBUTE_NAME;
    this.maximumAuthenticationLifetime = DEFAULT_MAXIMUM_AUTHENTICATION_LIFETIME;
    this.usernameCaseConversion = DEFAULT_USERNAME_CASE_CONVERSION;

    if (displayNameAttributeName != null && !displayNameAttributeName.isEmpty()) {
      this.displayNameAttributeName = displayNameAttributeName;
    }
    if (groupsAttributeName != null && !groupsAttributeName.isEmpty()) {
      this.groupsAttributeName = groupsAttributeName;
    }
    if (maximumAuthenticationLifetime != null && maximumAuthenticationLifetime > 0) {
      this.maximumAuthenticationLifetime = maximumAuthenticationLifetime;
    }
    this.usernameAttributeName = Util.fixEmptyAndTrim(usernameAttributeName);
    this.encryptionData = encryptionData;
    if (usernameCaseConversion != null && !usernameCaseConversion.isEmpty()) {
      this.usernameCaseConversion = Util.fixEmptyAndTrim(usernameCaseConversion);
    }
    LOG.finer(this.toString());
  }

  public SamlSecurityRealm(String signOnUrl, String idpMetadata, String displayNameAttributeName, String groupsAttributeName, Integer maximumAuthenticationLifetime, String usernameAttributeName, SamlEncryptionData encryptionData) {
    this(signOnUrl, idpMetadata, displayNameAttributeName, groupsAttributeName, maximumAuthenticationLifetime, usernameAttributeName, encryptionData, "none");
  }

  @Override
  public boolean allowsSignup() {
    return false;
  }

  @Override
  public SecurityComponents createSecurityComponents() {
    LOG.finer("createSecurityComponents");
    return new SecurityComponents(new AuthenticationManager() {

      public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof SamlAuthenticationToken) {
          return authentication;
        }
        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
      }

    }, new SamlUserDetailsService());
  }

  @Override
  public String getLoginUrl() {
    return "securityRealm/commenceLogin";
  }

  /**
   * /securityRealm/commenceLogin
   */
  public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) {
    LOG.fine("SamlSecurityRealm.doCommenceLogin called. Using consumerServiceUrl " + getConsumerServiceUrl());
    request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

    Saml2Client client = newClient();
    WebContext context = new J2ERequestContext(request);
    try {
      RedirectAction action = client.getRedirectAction(context, true, false);
      if (action.getType() == RedirectType.REDIRECT) {
        LOG.fine("REDIRECT : " + action.getLocation());
        return HttpResponses.redirectTo(action.getLocation());
      } else if (action.getType() == RedirectType.SUCCESS) {
        LOG.fine("SUCCESS : " + action.getContent());
        return HttpResponses.html(action.getContent());
      } else {
        throw new IllegalStateException("Received unexpected response type " + action.getType());
      }
    } catch (RequiresHttpAction e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * /securityRealm/finishLogin
   */
  public HttpResponse doFinishLogin(StaplerRequest request, StaplerResponse response) {
    LOG.finer("SamlSecurityRealm.doFinishLogin called");

    Saml2Client client = newClient();
    WebContext context = new J2EContext(request, response);
    Saml2Credentials credentials;
    try {
      credentials = client.getCredentials(context);
    } catch (RequiresHttpAction e) {
      throw new IllegalStateException(e);
    }

    Saml2Profile saml2Profile = client.getUserProfile(credentials, context);

    LOG.finer(saml2Profile.toString());
    // retrieve user display name
    String userFullName = null;
    List<?> names = (List<?>) saml2Profile.getAttribute(this.displayNameAttributeName);
    if (names != null && !names.isEmpty()) {
      userFullName = (String) names.get(0);
    }

    // prepare list of groups
    List<?> groups = (List<?>) saml2Profile.getAttribute(this.groupsAttributeName);
    if (groups == null) {
      groups = new ArrayList<String>();
    }

    // build list of authorities
    List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
    authorities.add(AUTHENTICATED_AUTHORITY);
    if (!groups.isEmpty()) {
      for (Object group : groups) {
        SamlGroupAuthority ga = new SamlGroupAuthority((String)group);
        authorities.add(ga);
      }
    }

    // getId and possibly convert, based on settings
    String username = getUsernameFromProfile(saml2Profile);
    if (this.usernameCaseConversion != null) {
      if (this.usernameCaseConversion.compareTo("lowercase") == 0) {
        username = username.toLowerCase();
      } else if (this.usernameCaseConversion.compareTo("uppercase") == 0) {
        username = username.toUpperCase();
      }
    }
    // create user data
    SamlUserDetails userDetails = new SamlUserDetails(username, authorities.toArray(new GrantedAuthority[authorities.size()]));
    SamlAuthenticationToken samlAuthToken = new SamlAuthenticationToken(userDetails);

    // initialize security context
    SecurityContextHolder.getContext().setAuthentication(samlAuthToken);
    SecurityListener.fireAuthenticated(userDetails);

    // update user full name if necessary
    if (userFullName != null && !userFullName.isEmpty()) {
      User user = User.current();
      if (user != null && userFullName.compareTo(user.getFullName()) != 0) {
        user.setFullName(userFullName);
        try {
          user.save();
        } catch (IOException e) {
          // even if it fails, nothing critical
          LOG.log(Level.WARNING, "Unable to save updated user data", e);
        }
      }
    }

    // redirect back to original page
    String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
    String redirectUrl = referer != null ? referer : baseUrl();
    return HttpResponses.redirectTo(redirectUrl);
  }

  /**
   * Extract a usable Username from the samlProfile object.
   * @param saml2Profile
   * @return
   */
  private String getUsernameFromProfile(Saml2Profile saml2Profile) {
    if (usernameAttributeName != null) {
      Object attribute = saml2Profile.getAttribute(usernameAttributeName);
      if (attribute instanceof String) {
        return (String) attribute;
      }
      if (attribute instanceof List) {
        return (String) ((List<?>)attribute).get(0);
      }
      LOG.log(Level.SEVERE, "Unable to get username from attribute {0} value {1}, Saml Profile {2}", new Object[] { usernameAttributeName, attribute, saml2Profile });
      LOG.log(Level.SEVERE, "Falling back to NameId {0}", saml2Profile.getId());
    }
    return saml2Profile.getId();
  }

  /**
   * /securityRealm/metadata
   *
   * URL request service method to expose the SP metadata to the user so that
   * they can configure their IdP.
   */
  public HttpResponse doMetadata(StaplerRequest request, StaplerResponse response) {
    Saml2Client client = newClient();

    return HttpResponses.plainText(client.printClientMetadata());
  }

  private Saml2Client newClient() {
    Preconditions.checkNotNull(idpMetadata);

    Saml2Client client = new Saml2Client();
    client.setIdpMetadata(idpMetadata);
    client.setCallbackUrl(getConsumerServiceUrl());
    client.setDestinationBindingType(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
    if (encryptionData != null) {
      client.setKeystorePath(encryptionData.getKeystorePath());
      client.setKeystorePassword(encryptionData.getKeystorePassword());
      client.setPrivateKeyPassword(encryptionData.getPrivateKeyPassword());
    }
    client.setMaximumAuthenticationLifetime(this.maximumAuthenticationLifetime);
    if (LOG.isLoggable(Level.FINE)) {
      LOG.fine(client.printClientMetadata());
    }
    return client;
  }

  /**
   * @see SecurityRealm#getPostLogOutUrl
   * Note: It does not call the logout service on SAML because the library does not implement it on this version,
   * it will be done when we upgrade the library.
   */
  @Override
  protected String getPostLogOutUrl(StaplerRequest req,@Nonnull Authentication auth) {
    LOG.log(Level.FINE,"Doing Logout {}",auth.getPrincipal());
    // if we just redirect to the root and anonymous does not have Overall read then we will start a login all over again.
    // we are actually anonymous here as the security context has been cleared
    if (Jenkins.getActiveInstance().hasPermission(Jenkins.READ)) {
        return super.getPostLogOutUrl(req, auth);
    }
    return req.getContextPath()+ "/" + SamlLogoutAction.POST_LOGOUT_URL;
  }

  @Override
  public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, javax.servlet.ServletException {
    super.doLogout(req,rsp);
      LOG.log(Level.FINEST,"Here we could do the SAML Single Logout");
      //TODO JENKINS-42448
  }

  private String baseUrl() {
    return Jenkins.getActiveInstance().getRootUrl();
  }

  private String getConsumerServiceUrl() {
    return baseUrl() + CONSUMER_SERVICE_URL_PATH;
  }

  public String getIdpMetadata() {
    return idpMetadata;
  }

  public void setIdpMetadata(String idpMetadata) {
    this.idpMetadata = idpMetadata;
  }

  public String getUsernameAttributeName() {
    return usernameAttributeName;
  }

  public void setUsernameAttributeName(String attribute) {
    this.usernameAttributeName = attribute;
  }

  public String getSpMetadata() {
    return newClient().printClientMetadata();
  }

  public String getDisplayNameAttributeName() {
    return displayNameAttributeName;
  }

  public String getGroupsAttributeName() {
    return groupsAttributeName;
  }

  public Integer getMaximumAuthenticationLifetime() {
    return maximumAuthenticationLifetime;
  }

  public SamlEncryptionData getEncryptionData() {
    return encryptionData;
  }

  public String getKeystorePath() {
    return encryptionData != null ? encryptionData.getKeystorePath() : null;
  }

  public String getKeystorePassword() {
    return encryptionData != null ? encryptionData.getKeystorePassword() : null;
  }

  public String getPrivateKeyPassword() {
    return encryptionData != null ? encryptionData.getPrivateKeyPassword() : null;
  }

  public String getUsernameCaseConversion() {
    return usernameCaseConversion;
  }

  public void setUsernameCaseConversion(String usernameCaseConversion) {
    this.usernameCaseConversion = usernameCaseConversion;
  }

  @Extension
  public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

    public DescriptorImpl() {
      super();
    }

    public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
      super(clazz);
    }

    @Override
    public String getDisplayName() {
      return "SAML 2.0";
    }

  }

  @Override
  public String toString() {
    final StringBuffer sb = new StringBuffer("SamlSecurityRealm{");
    sb.append("idpMetadata='").append(idpMetadata).append('\'');
    sb.append(", displayNameAttributeName='").append(displayNameAttributeName).append('\'');
    sb.append(", groupsAttributeName='").append(groupsAttributeName).append('\'');
    sb.append(", maximumAuthenticationLifetime=").append(maximumAuthenticationLifetime);
    sb.append(", usernameCaseConversion='").append(usernameCaseConversion).append('\'');
    sb.append(", usernameAttributeName='").append(usernameAttributeName).append('\'');
    sb.append(", encryptionData=").append(encryptionData);
    sb.append('}');
    return sb.toString();
  }
}
