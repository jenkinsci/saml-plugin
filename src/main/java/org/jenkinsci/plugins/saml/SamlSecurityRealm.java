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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import edu.umd.cs.findbugs.annotations.NonNull;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.saml.conf.Attribute;
import org.jenkinsci.plugins.saml.conf.AttributeEntry;
import org.jenkinsci.plugins.saml.user.SamlCustomProperty;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.pac4j.core.exception.http.FoundAction;
import org.pac4j.core.exception.http.WithLocationAction;
import org.pac4j.core.exception.http.OkAction;
import org.pac4j.core.exception.http.RedirectionAction;
import org.pac4j.core.exception.http.SeeOtherAction;
import org.pac4j.saml.profile.SAML2Profile;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.tasks.Mailer.UserProperty;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.apache.commons.codec.binary.Base64.decodeBase64;
import static org.apache.commons.codec.binary.Base64.isBase64;
import static org.opensaml.saml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;

/**
 * Authenticates the user via SAML.
 * This class is the main entry point to the plugin.
 * Uses Stapler (stapler.kohsuke.org) to bind methods to URLs.
 *
 * @see SecurityRealm
 */
public class SamlSecurityRealm extends SecurityRealm {
    public static final String DEFAULT_DISPLAY_NAME_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
    public static final String DEFAULT_GROUPS_ATTRIBUTE_NAME = "http://schemas.xmlsoap.org/claims/Group";
    public static final int DEFAULT_MAXIMUM_AUTHENTICATION_LIFETIME = 24 * 60 * 60; // 24h
    public static final String DEFAULT_USERNAME_CASE_CONVERSION = "none";
    public static final String SP_METADATA_FILE_NAME = "saml-sp-metadata.xml";
    public static final String IDP_METADATA_FILE_NAME = "saml-idp-metadata.xml";

    /**
     * form validation messages.
     */
    public static final String ERROR_ONLY_SPACES_FIELD_VALUE = "The field should have a value different than spaces";
    public static final String ERROR_NOT_VALID_NUMBER = "The field should be a number greater than 0 and lower than " + Integer.MAX_VALUE + ".";
    public static final String ERROR_MALFORMED_URL = "The url is malformed.";
    public static final String ERROR_IDP_METADATA_EMPTY = "The IdP Metadata can not be empty.";
    public static final String WARN_RECOMMENDED_TO_SET_THE_GROUPS_ATTRIBUTE = "It is recommended to set the groups attribute.";
    public static final String WARN_RECOMMENDED_TO_SET_THE_USERNAME_ATTRIBUTE = "It is recommended to set the username attribute.";
    public static final String WARN_RECOMMENDED_TO_SET_THE_EMAIL_ATTRIBUTE = "It is recommended to set the email attribute.";
    public static final String ERROR_NOT_POSSIBLE_TO_READ_KS_FILE = "It is not possible to read the keystore file.";
    public static final String ERROR_CERTIFICATES_COULD_NOT_BE_LOADED = "Any of the certificates in the keystore could not be loaded";
    public static final String ERROR_ALGORITHM_CANNOT_BE_FOUND = "the algorithm used to check the integrity of the keystore cannot be found";
    public static final String ERROR_NO_PROVIDER_SUPPORTS_A_KS_SPI_IMPL = "No Provider supports a KeyStoreSpi implementation for the specified type.";
    public static final String ERROR_WRONG_INFO_OR_PASSWORD = "The entry is a PrivateKeyEntry or SecretKeyEntry and the specified protParam does not contain the information needed to recover the key (e.g. wrong password)";
    public static final String ERROR_INSUFFICIENT_OR_INVALID_INFO = "The specified protParam were insufficient or invalid";

    /**
     * URL to process the SAML answers
     */
    public static final String CONSUMER_SERVICE_URL_PATH = "securityRealm/finishLogin";

    private static final Logger LOG = Logger.getLogger(SamlSecurityRealm.class.getName());
    private static final String REFERER_ATTRIBUTE = SamlSecurityRealm.class.getName() + ".referer";
    public static final String WARN_THERE_IS_NOT_KEY_STORE = "There is not keyStore to validate";
    public static final String ERROR_NOT_KEY_FOUND = "Not key found";
    public static final String SUCCESS = "Success";
    public static final String NOT_POSSIBLE_TO_GET_THE_METADATA = "Was not possible to get the Metadata from the URL ";
    public static final String CHECK_TROUBLESHOOTING_GUIDE = "\nIf you have issues check the troubleshoting guide at https://github.com/jenkinsci/saml-plugin/blob/master/doc/TROUBLESHOOTING.md";
    public static final String CHECK_MAX_AUTH_LIFETIME = "\nFor more info check 'Maximum Authentication Lifetime' at https://github.com/jenkinsci/saml-plugin/blob/master/doc/CONFIGURE.md#configuring-plugin-settings";

    public static final String WARN_KEYSTORE_NOT_SET = "Keystore is not set";
    public static final String WARN_PRIVATE_KEY_ALIAS_NOT_SET = "Key alias is not set";
    public static final String WARN_PRIVATE_KEYSTORE_PASS_NOT_SET = "Keystore password is not set";
    public static final String WARN_PRIVATE_KEY_PASS_NOT_SET = "Key password is not set";
    /**
     * configuration settings.
     */
    private String displayNameAttributeName;
    private String groupsAttributeName;
    private int maximumAuthenticationLifetime;
    private String emailAttributeName;

    private final String usernameCaseConversion;
    private final String usernameAttributeName;
    private final String logoutUrl;
    private String binding;

    private final SamlEncryptionData encryptionData;
    private final SamlAdvancedConfiguration advancedConfiguration;
    private final IdpMetadataConfiguration idpMetadataConfiguration;

    private List<AttributeEntry> samlCustomAttributes;

    /**
     * Jenkins passes these parameters in when you update the settings.
     * It does this because of the @DataBoundConstructor.
     *
     * @param idpMetadataConfiguration      How to obtain the IdP Metadata configuration.
     * @param displayNameAttributeName      attribute that has the displayname
     * @param groupsAttributeName           attribute that has the groups
     * @param maximumAuthenticationLifetime maximum time that an identification it is valid
     * @param usernameAttributeName         attribute that has the username
     * @param emailAttributeName            attribute that has the email
     * @param logoutUrl                     optional URL to redirect on logout
     * @param advancedConfiguration         advanced configuration settings
     * @param encryptionData                encryption configuration settings
     * @param usernameCaseConversion        username case sensitive settings
     * @param binding                       SAML binding method.
     * @param samlCustomAttributes          Custom Attributes to read from the SAML Responsse.
     * @throws IOException if it is not possible to write the IdP metadata file.
     */
    @DataBoundConstructor
    public SamlSecurityRealm(
            IdpMetadataConfiguration idpMetadataConfiguration,
            String displayNameAttributeName,
            String groupsAttributeName,
            Integer maximumAuthenticationLifetime,
            String usernameAttributeName,
            String emailAttributeName,
            String logoutUrl,
            SamlAdvancedConfiguration advancedConfiguration,
            SamlEncryptionData encryptionData,
            String usernameCaseConversion,
            String binding,
            List<AttributeEntry> samlCustomAttributes) throws IOException {
        super();
        this.idpMetadataConfiguration = idpMetadataConfiguration;
        this.usernameAttributeName = hudson.Util.fixEmptyAndTrim(usernameAttributeName);
        this.usernameCaseConversion = org.apache.commons.lang.StringUtils.defaultIfBlank(usernameCaseConversion, DEFAULT_USERNAME_CASE_CONVERSION);
        this.logoutUrl = hudson.Util.fixEmptyAndTrim(logoutUrl);
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
        if (org.apache.commons.lang.StringUtils.isNotBlank(emailAttributeName)) {
            this.emailAttributeName = hudson.Util.fixEmptyAndTrim(emailAttributeName);
        }
        this.advancedConfiguration = advancedConfiguration;
        this.encryptionData = encryptionData;
        this.binding = binding;
        this.samlCustomAttributes = samlCustomAttributes;

        this.idpMetadataConfiguration.createIdPMetadataFile();
        LOG.finer(this.toString());
    }

    // migration code for the new IdP metadata file
    @SuppressWarnings("unused")
    public Object readResolve() {
        File idpMetadataFile = new File(getIDPMetadataFilePath());
        if (!idpMetadataFile.exists() && idpMetadataConfiguration != null && idpMetadataConfiguration.getXml() != null){
            try {
                idpMetadataConfiguration.createIdPMetadataFile();
            } catch (IOException e) {
                LOG.log(Level.SEVERE, e.getMessage(), e);
            }
        }

        if(StringUtils.isEmpty(getBinding())){
            binding = SAML2_REDIRECT_BINDING_URI;
        }

        return this;
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        LOG.finer("createSecurityComponents");
        return new SecurityComponents(authentication -> {
            if (authentication instanceof SamlAuthenticationToken) {
                return authentication;
            }
            throw new BadCredentialsException("Unexpected authentication type: " + authentication);
        }, new SamlUserDetailsService());
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    /**
     * /securityRealm/commenceLogin
     *
     * @param request  http request.
     * @param response http response.
     * @param referer  referer.
     * @param from http request "from" parameter.
     * @return the http response.
     */
    @SuppressWarnings("unused")
    public HttpResponse doCommenceLogin(final StaplerRequest2 request, final StaplerResponse2 response, @QueryParameter
            String from, @Header("Referer") final String referer) {
        LOG.fine("SamlSecurityRealm.doCommenceLogin called. Using consumerServiceUrl " + getSamlPluginConfig().getConsumerServiceUrl());

        String redirectOnFinish = calculateSafeRedirect(from, referer);
        request.getSession().setAttribute(REFERER_ATTRIBUTE, redirectOnFinish);

        RedirectionAction action = new SamlRedirectActionWrapper(getSamlPluginConfig(), request, response).get();
        if (action instanceof SeeOtherAction || action instanceof FoundAction) {
            LOG.fine("REDIRECT : " + ((WithLocationAction)action).getLocation());
            return HttpResponses.redirectTo(((WithLocationAction)action).getLocation());
        } else if (action instanceof OkAction) {
            LOG.fine("SUCCESS : " + ((OkAction) action).getContent());
            return HttpResponses.literalHtml(((OkAction) action).getContent());
        } else {
            throw new IllegalStateException("Received unexpected response type " + action.getCode());
        }
    }

    /**
     * Check parameters "from" and "referer" to decide where is the safe URL to be redirected.
     * @param from http request "from" parameter.
     * @param referer referer header.
     * @return a safe URL to be redirected.
     */
    private String calculateSafeRedirect(String from, String referer) {
        String redirectURL;
        String rootUrl = baseUrl();
        //noinspection PointlessNullCheck
        if (from != null && Util.isSafeToRedirectTo(from)) {
            redirectURL = from;
        } else {
            if (referer != null && (referer.startsWith(rootUrl) || Util.isSafeToRedirectTo(referer))) {
                redirectURL = referer;
            } else {
                redirectURL = rootUrl;
            }
        }
        LOG.fine("Safe URL redirection: " + redirectURL);
        return redirectURL;
    }

    /**
     * /securityRealm/finishLogin
     *
     * @param request  http request.
     * @param response http response.
     * @return the http response.
     */
    @SuppressWarnings("unused")
    @RequirePOST
    public HttpResponse doFinishLogin(final StaplerRequest2 request, final StaplerResponse2 response) {
        LOG.finer("SamlSecurityRealm.doFinishLogin called");
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        // redirect back to original page
        String redirectUrl = referer != null ? referer : baseUrl();
        recreateSession(request);
        logSamlResponse(request);

        boolean saveUser = false;
        SAML2Profile saml2Profile;

        try {
            saml2Profile = new SamlProfileWrapper(getSamlPluginConfig(), request, response).get();
        } catch (BadCredentialsException e){
            LOG.log(Level.WARNING, "Unable to validate the SAML Response: " + e.getMessage()
                    + CHECK_MAX_AUTH_LIFETIME
                    + CHECK_TROUBLESHOOTING_GUIDE, e);
            return HttpResponses.redirectTo(getEffectiveLogoutUrl());
        }

        // getId and possibly convert, based on settings
        String username = loadUserName(saml2Profile);

        List<GrantedAuthority> authorities = loadGrantedAuthorities(saml2Profile);

        // create user data
        SamlUserDetails userDetails = new SamlUserDetails(username, authorities);

        SamlAuthenticationToken samlAuthToken = new SamlAuthenticationToken(userDetails);

        SecurityContextHolder.getContext().setAuthentication(samlAuthToken);
        SecurityListener.fireAuthenticated2(userDetails);
        User user = User.current();

        saveUser |= modifyUserFullName(user, saml2Profile);


        //retrieve user email
        List<String> emails = getListOfValues(saml2Profile.getAttribute(getEmailAttributeName()));
        saveUser |= modifyUserEmail(user, emails);

        saveUser |= modifyUserSamlCustomAttributes(user, saml2Profile);

        try {
            if (user != null && saveUser) {
                user.save();
            }
        } catch (IOException e) {
            // even if it fails, nothing critical
            LOG.log(Level.WARNING, "Unable to save updated user data", e);
        }

        SecurityListener.fireLoggedIn(userDetails.getUsername());
        return HttpResponses.redirectTo(redirectUrl);
    }

    /**
     * retrieve the value of an attribute in a list for consistence with the reset of attributes manage.
     * @return the values of the attribute in a list.
     */
    @NonNull
    private List<String> getListOfValues(Object attributeValue) {
        @SuppressWarnings("unchecked")
        List<String> listOfValues = Collections.emptyList();
        if(attributeValue instanceof List) {
            listOfValues = (List<String>) attributeValue;
        } else if (attributeValue instanceof String){
            listOfValues = Collections.singletonList((String) attributeValue);
        }
        return listOfValues;
    }

    private String getEffectiveLogoutUrl() {
            return StringUtils.isNotBlank(getLogoutUrl()) ? getLogoutUrl() : Jenkins.get().getRootUrl() + SamlLogoutAction.POST_LOGOUT_URL;
    }

    /**
     * check if a request contains a session, if so, it invalidates the session and create new one to avoid session
     * fixation.
     * @param request request.
     */
    private void recreateSession(StaplerRequest2 request) {
        HttpSession session = request.getSession(false);
        if(session != null){
            LOG.finest("Invalidate previous session");
            // avoid session fixation
            session.invalidate();
        }
        request.getSession(true);
    }

    private boolean modifyUserSamlCustomAttributes(User user, SAML2Profile profile) {
        boolean saveUser = false;
        if(!getSamlCustomAttributes().isEmpty() && user != null){
            SamlCustomProperty userProperty = new SamlCustomProperty(new ArrayList<>());

            for (AttributeEntry attributeEntry : getSamlCustomAttributes()) {
                if(attributeEntry instanceof Attribute){
                    Attribute attr =  (Attribute) attributeEntry;
                    Object attrValue = profile.getAttribute(attr.getName());
                    if (attrValue != null) {
                        SamlCustomProperty.Attribute item = new SamlCustomProperty.Attribute(attr.getName(),attr.getDisplayName());
                        item.setValue(attrValue.toString());
                        userProperty.getAttributes().add(item);
                    }
                }
            }
            try {
                user.addProperty(userProperty);
            } catch (IOException e) {
                LOG.log(Level.SEVERE, "Could not update user SAML custom attributes", e);
            }
            saveUser = true;
        }
        return saveUser;
    }

    /**
     * Tries to log the content of the SAMLResponse even it is not valid.
     * @param request Request received in doFinishLogin, it should be a SAMLResponse.
     */
    private void logSamlResponse(StaplerRequest2 request) {
        if(LOG.isLoggable(Level.FINEST)){
            try {
                String samlResponse = request.getParameter("SAMLResponse");
                if(isBase64(samlResponse)) {
                    LOG.finest("SAMLResponse XML:" + new String(decodeBase64(samlResponse), request.getCharacterEncoding()));
                } else {
                    LOG.finest("SAMLResponse XML:" + samlResponse);
                }
            } catch (Exception e) {
                LOG.finest("No UTF-8 SAMLResponse XML");
                try(InputStream in = request.getInputStream()) {
                    LOG.finest(IOUtils.toString(in, request.getCharacterEncoding()));
                } catch (IOException e1) {
                    LOG.finest("Was not possible to read the request");
                }
            }
        }
    }

    private String baseUrl() {
        return  Jenkins.get().getRootUrl();
    }

    /**
     * load the username from the profile and set the correct characters case.
     *
     * @param saml2Profile SAML Profile.
     * @return the user name.
     */
    private String loadUserName(SAML2Profile saml2Profile) {
        String username = getUsernameFromProfile(saml2Profile);
        if ("lowercase".compareTo(getUsernameCaseConversion()) == 0) {
            username = username.toLowerCase();
        } else if ("uppercase".compareTo(getUsernameCaseConversion()) == 0) {
            username = username.toUpperCase();
        }
        return username;
    }

    /**
     * modify the fullname in the current user taken it from the SAML Profile.
     *
     * @param user         current user.
     * @param saml2Profile SAML Profile.
     * @return true if the current user is modified.
     */
    private boolean modifyUserFullName(User user, SAML2Profile saml2Profile) {
        boolean saveUser = false;
        // retrieve user display name
        String userFullName = null;
        List<String> names = getListOfValues(saml2Profile.getAttribute(getDisplayNameAttributeName()));
        if (!names.isEmpty()) {
            userFullName = names.get(0);
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
     *
     * @param saml2Profile SAML Profile.
     * @return granted authorities.
     */
    @Restricted(NoExternalUse.class) // Visible for testing
    List<GrantedAuthority> loadGrantedAuthorities(SAML2Profile saml2Profile) {
        // prepare list of groups
        List<String> groups = getListOfValues(saml2Profile.getAttribute(getGroupsAttributeName())) ;

        // build list of authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(AUTHENTICATED_AUTHORITY2);
        int countEmptyGroups = 0;
        for (String group : groups) {
            if (StringUtils.isNotBlank(group)) {
                authorities.add(new SimpleGrantedAuthority(group));
            } else {
                countEmptyGroups++;
            }
        }
        if (countEmptyGroups > 0) {
            LOG.log(Level.WARNING, String.format("Found %d empty groups in the saml profile for %s. Please check the SAML backend configuration.", countEmptyGroups, getUsernameFromProfile(saml2Profile)));
        }
        return authorities;
    }

    /**
     * set the user email. It will take the first not empty value on the list of email.
     *
     * @param user   current user.
     * @param emails user emails.
     * @return true if the current user is modified.
     */
    private boolean modifyUserEmail(User user, @NonNull List<String> emails) {
        String userEmail = null;
        boolean saveUser = false;
        if (emails.isEmpty()) {
            LOG.warning("There is not Email attribute '" + getEmailAttributeName() + "' for user : " + user.getId());
            return false;
        }

        for (String item : emails) {
            if (StringUtils.isNotEmpty(item)) {
                userEmail = item;
                break;
            }
        }

        if (StringUtils.isBlank(userEmail)) {
            LOG.warning("The Email is blank for user : " + user.getId());
        }

        try {
            if (user != null && StringUtils.isNotBlank(userEmail)) {
                UserProperty currentUserEmailProperty = user.getProperty(UserProperty.class);
                if (currentUserEmailProperty == null ||
                        userEmail.compareTo(StringUtils.defaultIfBlank(currentUserEmailProperty.getAddress(), "")) != 0) {
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
     *
     * @param saml2Profile user profile
     * @return the username or if it is not possible to get the attribute the profile ID
     */
    private String getUsernameFromProfile(SAML2Profile saml2Profile) {
        if (getUsernameAttributeName() != null) {
            List<String> attributes = getListOfValues(saml2Profile.getAttribute(getUsernameAttributeName()));
            if (!attributes.isEmpty()) {
                return attributes.get(0);
            }
            LOG.log(Level.SEVERE, "Unable to get username from attribute {0} value {1}, Saml Profile {2}",
                    new Object[]{getUsernameAttributeName(), attributes.toString(), saml2Profile});
            LOG.log(Level.SEVERE, "Falling back to NameId {0}", saml2Profile.getId());
        }
        return saml2Profile.getId();
    }

    static String getIDPMetadataFilePath() {
        return Jenkins.get().getRootDir().getAbsolutePath() + File.separator + IDP_METADATA_FILE_NAME;
    }

    static String getSPMetadataFilePath() {
        return Jenkins.get().getRootDir().getAbsolutePath() + File.separator + SP_METADATA_FILE_NAME;
    }

    /**
     * /securityRealm/metadata
     * <p>
     * URL request service method to expose the SP metadata to the user so that
     * they can configure their IdP.
     *
     * @param request  http request.
     * @param response http response.
     * @return the http response.
     */
    @SuppressWarnings("unused")
    public HttpResponse doMetadata(StaplerRequest2 request, StaplerResponse2 response) {
        return new SamlSPMetadataWrapper(getSamlPluginConfig(), request, response).get();
    }

    /**
     * @see SecurityRealm#getPostLogOutUrl2
     * Note: It does not call the logout service on SAML because the library does not implement it on this version,
     * it will be done when we upgrade the library.
     */
    @SuppressWarnings("deprecation")
    @Override
    protected String getPostLogOutUrl2(StaplerRequest2 req, @NonNull Authentication auth) {
        LOG.log(Level.FINE, "Doing Logout {}", auth.getPrincipal());
        // if we just redirect to the root and anonymous does not have Overall read then we will start a login all over again.
        // we are actually anonymous here as the security context has been cleared
        if (Jenkins.get().hasPermission(Jenkins.READ) && StringUtils.isBlank(getLogoutUrl())) {
            return super.getPostLogOutUrl2(req, auth);
        }
        return getEffectiveLogoutUrl();
    }

    @Override
    @RequirePOST
    public void doLogout(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException, ServletException {
        Jenkins.get().checkPermission(Jenkins.READ);
        super.doLogout(req, rsp);
        LOG.log(Level.FINEST, "Here we could do the SAML Single Logout");
    }

    /**
     * This method is overwritten due to SAML has no way to retrieve the members of a Group and this cause issues on
     * some Authorization plugins. Because of that we have to implement SamlGroupDetails
     */
    @Override
    public GroupDetails loadGroupByGroupname2(String groupname, boolean fetchMembers) throws org.springframework.security.core.userdetails.UsernameNotFoundException {
        GroupDetails dg = new SamlGroupDetails(groupname);

        if (dg.getMembers().isEmpty()) {
            throw new UserMayOrMayNotExistException2(groupname);
        }
        return dg;
    }

    /**
     * @return plugin configuration parameters.
     */
    public SamlPluginConfig getSamlPluginConfig() {
        return new SamlPluginConfig(displayNameAttributeName, groupsAttributeName,
                                    maximumAuthenticationLifetime, emailAttributeName, idpMetadataConfiguration, usernameCaseConversion,
                                    usernameAttributeName, logoutUrl, binding, encryptionData, advancedConfiguration);
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "SAML 2.0";
        }

        @RequirePOST
        public FormValidation doCheckLogoutUrl(@QueryParameter String logoutUrl) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkUrlFormat(logoutUrl);
        }

        @RequirePOST
        public FormValidation doCheckDisplayNameAttributeName(@QueryParameter String displayNameAttributeName) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringFormat(displayNameAttributeName);
        }

        @RequirePOST
        public FormValidation doCheckGroupsAttributeName(@QueryParameter String groupsAttributeName) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringAttributeFormat(groupsAttributeName, SamlSecurityRealm.WARN_RECOMMENDED_TO_SET_THE_GROUPS_ATTRIBUTE, true);
        }

        @RequirePOST
        public FormValidation doCheckUsernameAttributeName(@QueryParameter String usernameAttributeName) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringAttributeFormat(usernameAttributeName, SamlSecurityRealm.WARN_RECOMMENDED_TO_SET_THE_USERNAME_ATTRIBUTE, true);
        }

        @RequirePOST
        public FormValidation doCheckEmailAttributeName(@QueryParameter String emailAttributeName) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkStringAttributeFormat(emailAttributeName, SamlSecurityRealm.WARN_RECOMMENDED_TO_SET_THE_EMAIL_ATTRIBUTE, true);
        }

        @RequirePOST
        public FormValidation doCheckMaximumAuthenticationLifetime(@QueryParameter String maximumAuthenticationLifetime) {
            Jenkins.get().checkPermission(Jenkins.ADMINISTER);
            return SamlFormValidation.checkIntegerFormat(maximumAuthenticationLifetime);
        }
    }

    public String getUsernameAttributeName() {
        return usernameAttributeName;
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

    public String getBinding() {
        return binding;
    }

    public SamlEncryptionData getEncryptionData() {
        return encryptionData;
    }

    public String getUsernameCaseConversion() {
        return usernameCaseConversion;
    }

    public String getEmailAttributeName() {
        return emailAttributeName;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public IdpMetadataConfiguration getIdpMetadataConfiguration() {
        return idpMetadataConfiguration;
    }

    @NonNull
    public List<AttributeEntry> getSamlCustomAttributes() {
        if(samlCustomAttributes == null){
            return java.util.Collections.emptyList();
        }
        return samlCustomAttributes;
    }

    public void setSamlCustomAttribute(List<AttributeEntry> samlCustomAttributes) {
        this.samlCustomAttributes = samlCustomAttributes;
    }

    @Override
    public String toString() {
        return "SamlSecurityRealm{" + getSamlPluginConfig().toString() + '}';
    }

}
