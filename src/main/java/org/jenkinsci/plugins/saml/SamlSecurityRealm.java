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
import hudson.security.AuthorizationStrategy;
import hudson.security.GroupDetails;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.FormValidation;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer.UserProperty;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
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
import org.springframework.dao.DataAccessException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
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
  public static final String EXPIRATION_ATTRIBUTE = SamlSecurityRealm.class.getName() + ".expiration";

  private static final Logger LOG = Logger.getLogger(SamlSecurityRealm.class.getName());
  private static final String REFERER_ATTRIBUTE = SamlSecurityRealm.class.getName() + ".referer";
  private static final String DEFAULT_DISPLAY_NAME_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
  private static final String DEFAULT_GROUPS_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/claims/Group";
  private static final int DEFAULT_MAXIMUM_AUTHENTICATION_LIFETIME = 24 * 60 * 60; // 24h
  private static final String DEFAULT_USERNAME_CASE_CONVERSION = "none";
  private static final String DEFAULT_EMAIL_ATTRIBUTE_NAME = "email";

  private String displayNameAttributeName;
  private String groupsAttributeName;
  private int maximumAuthenticationLifetime;
  private String emailAttributeName;

  private final String idpMetadata;
  private final String usernameCaseConversion;
  private final String usernameAttributeName;
  private final String logoutUrl;

  private SamlEncryptionData encryptionData;
  private SamlAdvancedConfiguration advancedConfiguration;

  /**
   * Jenkins passes these parameters in when you update the settings.
   * It does this because of the @DataBoundConstructor
   *
   * @param idpMetadata Identity provider Metadata
   * @param displayNameAttributeName attribute that has the displayname
   * @param groupsAttributeName attribute that has the groups
   * @param maximumAuthenticationLifetime maximum time that an identification it is valid
   * @param usernameAttributeName attribute that has the username
   * @param emailAttributeName attribute that has the email
   * @param logoutUrl optional URL to redirect on logout
   * @param advancedConfiguration advanced configuration settings
   * @param encryptionData encryption configuration settings
   * @param usernameCaseConversion username case sensitive settings
   */
  @DataBoundConstructor
  public SamlSecurityRealm(String signOnUrl, String idpMetadata, String displayNameAttributeName, String groupsAttributeName, Integer maximumAuthenticationLifetime, String usernameAttributeName, String emailAttributeName, String logoutUrl, SamlAdvancedConfiguration advancedConfiguration, SamlEncryptionData encryptionData, String usernameCaseConversion) {
    super();
    this.idpMetadata = Util.fixEmptyAndTrim(idpMetadata);
    this.displayNameAttributeName = DEFAULT_DISPLAY_NAME_ATTRIBUTE_NAME;
    this.groupsAttributeName = DEFAULT_GROUPS_ATTRIBUTE_NAME;
    this.maximumAuthenticationLifetime = DEFAULT_MAXIMUM_AUTHENTICATION_LIFETIME;

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
    this.advancedConfiguration = advancedConfiguration;
    this.encryptionData = encryptionData;
    this.usernameCaseConversion = StringUtils.defaultIfBlank(usernameCaseConversion,DEFAULT_USERNAME_CASE_CONVERSION);

    if (StringUtils.isNotBlank(emailAttributeName)) {
      this.emailAttributeName = Util.fixEmptyAndTrim(emailAttributeName);
    }

    this.logoutUrl = Util.fixEmptyAndTrim(logoutUrl);
    LOG.finer(this.toString());
  }

  public SamlSecurityRealm(String signOnUrl, String idpMetadata, String displayNameAttributeName, String groupsAttributeName, Integer maximumAuthenticationLifetime, String usernameAttributeName, String emailAttributeName, String logoutUrl, SamlAdvancedConfiguration advancedConfiguration, SamlEncryptionData encryptionData) {
    this(signOnUrl, idpMetadata, displayNameAttributeName, groupsAttributeName, maximumAuthenticationLifetime, usernameAttributeName, emailAttributeName, logoutUrl, advancedConfiguration, encryptionData, "none");
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
    boolean saveUser = false;

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

    // getId and possibly convert, based on settings
    String username = loadUserName(saml2Profile);

    List<GrantedAuthority> authorities = loadGrantedAuthorities(saml2Profile);

    // create user data
    SamlUserDetails userDetails = new SamlUserDetails(username, authorities.toArray(new GrantedAuthority[authorities.size()]));
    // set session expiration, if needed.

    if (getMaximumSessionLifetime() != null) {
      request.getSession().setAttribute(
        EXPIRATION_ATTRIBUTE,
        System.currentTimeMillis() + 1000 * getMaximumSessionLifetime()
      );
    }

    SamlAuthenticationToken samlAuthToken = new SamlAuthenticationToken(userDetails, request.getSession());

    // initialize security context
    SecurityContextHolder.getContext().setAuthentication(samlAuthToken);
    SecurityListener.fireAuthenticated(userDetails);
    User user = User.current();

    saveUser |= modifyUserFullName(user, saml2Profile);


    //retrieve user email
    saveUser |= modifyUserEmail(user,(List<?>) saml2Profile.getAttribute(getEmailAttributeName()));

    try {
      if(user != null && saveUser) {
        user.save();
      }
    } catch (IOException e) {
      // even if it fails, nothing critical
      LOG.log(Level.WARNING, "Unable to save updated user data", e);
    }

    SecurityListener.fireLoggedIn(userDetails.getUsername());

    // redirect back to original page
    String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
    String redirectUrl = referer != null ? referer : baseUrl();
    return HttpResponses.redirectTo(redirectUrl);
  }

  /**
   * load the username from the profile and set the correct characters case.
   * @param saml2Profile SAML Profile.
   * @return the user name.
   */
  private String loadUserName(Saml2Profile saml2Profile) {
    String username = getUsernameFromProfile(saml2Profile);
    if (this.usernameCaseConversion != null) {
      if (this.usernameCaseConversion.compareTo("lowercase") == 0) {
        username = username.toLowerCase();
      } else if (this.usernameCaseConversion.compareTo("uppercase") == 0) {
        username = username.toUpperCase();
      }
    }
    return username;
  }

  /**
   * modify the fullname in the current user taken it from the SAML Profile.
   * @param user current user.
   * @param saml2Profile SAML Profile.
   * @return true if the current user is modified.
   */
  private boolean modifyUserFullName(User user, Saml2Profile saml2Profile) {
    boolean saveUser = false;
    // retrieve user display name
    String userFullName = null;
    List<?> names = (List<?>) saml2Profile.getAttribute(this.displayNameAttributeName);
    if (names != null && !names.isEmpty()) {
      userFullName = (String) names.get(0);
    }

    // update user full name if necessary
    if (user != null && StringUtils.isNotBlank(userFullName)) {
      if (userFullName.compareTo(user.getFullName()) != 0) {
        user.setFullName(userFullName);
        saveUser = true;
      }
    }
    return saveUser;
  }

  /**
   * load the granted authorities from the SAML Profile.
   * @param saml2Profile SAML Profile.
   * @return granted authorities.
   */
  private List<GrantedAuthority> loadGrantedAuthorities(Saml2Profile saml2Profile) {
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
    return authorities;
  }

  /**
   * set the user email.
   * @param user current user.
   * @param emails user emails.
   * @return true if the current user is modified.
   */
  private boolean  modifyUserEmail(User user, List<?> emails) {
    String userEmail = null;
    boolean saveUser = false;
    if (emails != null && !emails.isEmpty()) {
      userEmail = (String) emails.get(0);
    }

    try {
      if(user != null && StringUtils.isNotBlank(userEmail)){
        UserProperty currentUserEmailProperty = user.getProperty(UserProperty.class);
        if (currentUserEmailProperty!=null
                && userEmail.compareTo(StringUtils.defaultIfBlank(currentUserEmailProperty.getAddress(),"")) != 0) {
          // email address
          UserProperty emailProperty = new UserProperty(userEmail);
          user.addProperty(emailProperty);
          saveUser = true;
        }
      }
    } catch (IOException e) {
      LOG.log(Level.SEVERE, "Could not update user email", e);
    }
    return saveUser;
  }

  /**
   * Extract a usable Username from the samlProfile object.
   * @param saml2Profile user profile
   * @return the username or if it is not possible to get the attribute the profile ID
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
    if (getEncryptionData() != null) {
      client.setKeystorePath(getKeystorePath());
      client.setKeystorePassword(getKeystorePassword());
      client.setPrivateKeyPassword(getPrivateKeyPassword());
    }

    client.setMaximumAuthenticationLifetime(this.maximumAuthenticationLifetime);

    if(getAdvancedConfiguration()!=null) {

      // request forced authentication at the IdP, if selected
      client.setForceAuth(getForceAuthn());

      // override the default EntityId for this SP, if one is set
      if (getSpEntityId() != null) {
        client.setSpEntityId(getSpEntityId());
      }

      // if a specific authentication type (authentication context class
      // reference) is set, include it in the request to the IdP, and request
      // that the IdP uses exact matching for authentication types
      if (getAuthnContextClassRef() != null) {
        client.setAuthnContextClassRef(getAuthnContextClassRef());
        client.setComparisonType("exact");
      }
    }
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
    if (Jenkins.getActiveInstance().hasPermission(Jenkins.READ) && StringUtils.isBlank(getLogoutUrl())) {
        return super.getPostLogOutUrl(req, auth);
    }
    return StringUtils.isNotBlank(getLogoutUrl()) ? getLogoutUrl() : Jenkins.getActiveInstance().getRootUrl() + SamlLogoutAction.POST_LOGOUT_URL;
  }

  @Override
  public void doLogout(StaplerRequest req, StaplerResponse rsp) throws IOException, javax.servlet.ServletException {
    super.doLogout(req,rsp);
      LOG.log(Level.FINEST,"Here we could do the SAML Single Logout");
      //TODO JENKINS-42448
  }

  @Override
  public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
    GroupDetails dg =  new SamlGroupDetails(groupname);

    if(dg.getMembers().isEmpty()){
      throw new UserMayOrMayNotExistException(groupname);
    }
    return dg;
  }

  @Override
  public GroupDetails loadGroupByGroupname(String groupname, boolean fetchMembers)
          throws UsernameNotFoundException, DataAccessException {
    GroupDetails dg = loadGroupByGroupname(groupname);
    if(fetchMembers){
      dg.getMembers();
    }
    return dg;
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

  public String getUsernameAttributeName() {
    return usernameAttributeName;
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

  public SamlAdvancedConfiguration getAdvancedConfiguration() {
    return advancedConfiguration;
  }

  public Boolean getForceAuthn() {
    return advancedConfiguration != null ? advancedConfiguration.getForceAuthn() : Boolean.FALSE;
  }

  public String getAuthnContextClassRef() {
    return advancedConfiguration != null ? advancedConfiguration.getAuthnContextClassRef() : null;
  }

  public String getSpEntityId() {
    return advancedConfiguration != null ? advancedConfiguration.getSpEntityId() : null;
  }

  public Integer getMaximumSessionLifetime() {
    return advancedConfiguration != null ? advancedConfiguration.getMaximumSessionLifetime() : null;
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

  public String getEmailAttributeName() { return emailAttributeName; }

  public String getLogoutUrl() { return logoutUrl; }

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

  public FormValidation doCheckLogoutUrl(@QueryParameter String logoutUrl) {
    if (logoutUrl == null || logoutUrl.isEmpty()) {
      return FormValidation.ok();
    }
    try {
      new URL(logoutUrl);
    } catch (MalformedURLException e) {
      return FormValidation.error("The url is malformed.", e);
    }
    return FormValidation.ok();
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
    sb.append(", advancedConfiguration=").append(advancedConfiguration);
    sb.append('}');
    return sb.toString();
  }
}
