Configuring Jenkins
----------------

* Go to "Configure Global Security"
* Check "Enable security"
* Select "SAML 2.0"
* Configure plugin settings
* Hit Save

You'll also need to turn on authorization for the SAML settings to take effect. As long as the anonymous user can take all actions,
Jenkins won't try to log the user in.

![](images/SAMLPluginSetting.png)

## Configuring plugin settings

* **Metadata**
  * **IdP Metadata** - Identity Provider Metadata in XML format. Usually, identity providers that support SAML expose metadata in XML form by public URL.
  This metadata should be downloaded and copy-pasted to this field (not need if you have set the IdP Metadata URL).
  * **IdP Metadata URL** - The Identity Provider metadata file source URL (not need if you have set the IdP Metadata).
    * **Refresh Period** - The period of minutes we will wait until refresh the IdP Metadata. Set it to 0 to not update the metadata.
* **Display Name Attribute** - Name of the attribute that carries the display name (optional). If not specified, the username is used.
* **Group Attribute** - Name of the attribute that carries user groups (optional).
This attribute must have separate AttributeValue elements per role (so for example, they can't be concatenated to a single string).
* **Maximum Authentication Lifetime** - Number of seconds since the user was authenticated in IdP while his authentication is considering as active.
If you often get "No valid subject assertion found in response" or "Authentication issue instant is too old or in the future"
then most probably you need to increase this value. Set this setting to value greater than the session lifetime on IdP
Default is 24h * 60 min * 60 sec = 86400
* **Username Attribute** - Name of the attribute that carries user name which will be used as the Jenkins ID (optional).
If not specified, the SAML profile ID will be used.
* **Email Attribute** - Fill name of email attribute in SAML response.
* **Username Case Conversion** - The ID returned from SAML is used as the username for Authorization, which is usually case sensitive.
To make it easier to match with user definition in the policy, the returned value can be converted.
__Caution!__ Be aware of case in Authorization strategy as you may lose access rights if they do not match
  * None - will not change return value (default)
  * Lowercase - convert to lowercase
  * Uppercase - convert to uppercase
* **Data Binding Method** - SAML Plugin supports two method of redirection binding HTTP-Redirect and HTTP-POST, by default HTTP-Redirect is used.
Check supported binding redirection types of your IdP.
  * urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect
  * urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST
* **Logout URL** - The url of your Identity Provider where you want to be redirected once logout.
* **Advanced Configuration** - You could enable this options to use SAML ForceAuthn to force logins at our IdP,
AuthnContextClassRef to override the default authentication mechanism, and force multi-factor authentication;
you also could set the sessions on Jenkins to be shorter than those on your IdP.
  * **Force Authentication** - Whether to request the SAML IdP to force (re)authentication of the user,
  rather than allowing an existing session with the IdP to be reused. Off by default
  * **Authentication Context** - If this field is not empty, request that the SAML IdP uses a specific authentication context,
  rather than its default. Check with the IdP administrators to find out which authentication contexts are available
  * **SP Entity ID** - If this field is not empty, it overrides the default Entity ID for this Service Provider.
  Service Provider Entity IDs are usually a URL, like ***http://jenkins.example.org/securityRealm/finishLogin***.
* **Encryption** - If your provider requires encryption or signing, you can specify the keystore details here that should be used.
If you do not specify a keystore, the plugin would create one with a key that is valid for a year,
this key would be recreate when it expires, by default the key is not exposed in the SP metadata if you do not enable signing.
  * **Keystore path** - The path to the keystore file created with the keygen command.
  * **Key Alias** - The alias used in the -alias argument of the keytool< command.
  * **Keystore password** - The password used in the -storepass argument of the keytool command.
  * **Private Key password** - The password used in the -keypass argument of keytool.
  * **Auth Request Signature** - Enable signature of the Redirect Binding Auth Request,
  If you enable it the encryption and signing key would available in the SP metadata file and URL (JENKINS_URL/securityRealm/metadata).
  
The attribute is sometimes called a claim, and for some IdPs it has a fixed structure, e.g. a URI. So in some documentation,
you might see the term URI of the claim instead of the name of the attribute.

## Configuring groups security

If your IdP provides the group(s) a user belongs to via an attribute of the SAML response,
you can use this to configure role-based security with the [Role Strategy Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Role+Strategy+Plugin).

* Go to "Configure Global Security"
* Check "Role-Based Strategy" in Authorization section
* Hit Save
* Go to "Manage and Assign Roles" => "Manage Roles". Here you define roles, which have permissions.
* Configure "Project roles" section with roles that match your needs. These roles can be named anything you like.
* Hit Save
* Go to "Manage and Assign Roles" => "Assign Roles". Here you attach the SAML-provided groups to the roles you defined in the previous step.
* In "User/group to add" you enter the name of the SAML group you want to attach to a role. (Group names are case sensitive)
* Once a group is added, you can attach it to one or more roles.
* Hit save.

## Configuring Identity Provider (IdP)

On the IdP side, you need to specify the location in Jenkins which accepts the HTTP POST with the authentication data (SAML response).
This is [URL of Jenkins]/securityRealm/finishLogin. This Jenkins URL  it is obtained from "Jenkins URL" field on Configure System,
if you use a load balancer or reverse proxy or another kind of redirection in the middle check that the real URL it is configured on Configure System,
if not the SAML Response will be not valid.  So for example ***https://jenkins.example.com/securityRealm/finishLogin***.

You also need to specify the **entity ID** (sometimes called **Audience**), by default, this is the same URL, on advanced settings you can configure it.

Not all IdPs use the same terminology, these are the fields for some common IdPs:

### Okta

[How do I setup OKTA as Identity Provider in Jenkins?](https://support.cloudbees.com/hc/en-us/articles/115000105752)

### OneLogin

These are the fields for the OneLogin SAML Test (IdP) app template. Other app templates might use different names,
see [their docs on the SAML connector](https://onelogin.service-now.com/support?id=kb_article&sys_id=93f95543db109700d5505eea4b96198f) for more information.

* SAML Consumer URL
* SAML Audience
* SAML Recipient

### ADFS

[Configure ADFS](ADFS_CONFIG.md)

### Azure

[Configure Azure](CONFIGURE_AZURE.md)

### Configuring Single Log Out

When using a proxy like Apache, it is possible to catch the logout with a **mod_rewrite** and redirect the browser to the Identity Provider for Single Log Out.

As the standard logout of Jenkins will be bypassed, the JSESSIONID should also be reset.

Example code for **mod_rewrite**

```
RewriteEngine On
#### find the unique session identifier using RewriteCond ####
RewriteCond %{HTTP_COOKIE} (JSESSIONID.[a-z0-9]+)

#### redirect the logout URL to the IdP logout (in this case SimpleSAMLphp) and reset the session cookie ####
RewriteRule ^/?logout$ https://idp.example.com/simplesamlphp/saml2/idp/initSLO.php?RelayState=https://jenkins.example.com/ 
```

## Backup files considerations

If you do not configure encryption settings The plugin creates a key pair automatically and stores them in "JENKINS_HOME/saml-jenkins-keystore.jks",
then store the data related into "JENKINS_HOME/saml-jenkins-keystore.xml", you can grab the public key from "JENKINS_HOME/saml-sp-metadata.xml".

If you configured the encryption settings, you only have to copy the key store and the config files (you should maintain
the secrets also). The default key store is "JENKINS_HOME/saml-jenkins-keystore.jks"
the configuration is in "JENKINS_HOME/saml-jenkins-keystore.xml" some data is encrypted, so it is not for manual manage,
and it only is valid for a Jenkins with the same JENKINS_HOME/secrets.

You need the following files to restore the SAML configuration

JENKINS_HOME/config.xml
JENKINS_HOME/saml-jenkins-keystore.jks
JENKINS_HOME/saml-jenkins-keystore.xml
JENKINS_HOME/saml-ipd-metadata.xml
JENKINS_HOME/saml-sp-metadata.xml
Also you need the same secret.key, if not the configuration is impossible to unencrypt
but in any case, you use to make a backup of your full JENKINS_HOME to make your Jenkins instance work properly
(not only SAML Plugin), I recommend you to take a look at this [CloudBees KB](https://support.cloudbees.com/hc/en-us/articles/216241937-Migration-Guide-CloudBees-Jenkins-Platform-and-CloudBees-Jenkins-Team-)

Troubleshooting
-------------------
[Troubleshooting](TROUBLESHOOTING.md)

