Example: Setting up Active Directory Federation Services (ADFS) to use with Jenkins
----------------

*Note:* replace adfs.example.com with the name of your ADFS, replace jenkins.example.com with the name of your Jenkins host.

**On the Jenkins side:**
* Download the IdP file to paste into the Jenkins config from your ADFS. It is generally exposed under the following URL:

```
https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml
```

* Set the system property `-Dorg.apache.xml.security.ignoreLineBreaks=true` when starting Jenkins.


**On the Windows side:**

Open the Management console (mmc), make sure you have the AD FS Management snap-in. Add a Relying Party Trust:

![](images/Screen_Shot_2015-12-10_at_16.13.52.png)

Go through the wizard. The properties at the end should look like indicated on the following screens.

**Monitoring:** unmodified | **Identifiers:** The relying party identifier is: http://jenkins.example.org/securityRealm/finishLogin
------------ | -------------
![](images/Screen_Shot_2015-12-10_at_16.11.42.png) | ![](images/Screen_Shot_2015-12-10_at_16.11.44.png)

**Encryption:** import key from the JENKINS_HOME/saml-sp.metadata.xml file | **Signature:** import key from the JENKINS_HOME/saml-sp.metadata.xml file
------------ | -------------
![](images/Screen_Shot_2015-12-10_at_16.11.46.png) | ![](images/Screen_Shot_2015-12-10_at_16.11.49.png)

**Accepted Claims:** unmodified | **Organization:** unmodified
------------ | -------------
![](images/Screen_Shot_2015-12-10_at_16.11.51.png) | ![](images/Screen_Shot_2015-12-10_at_16.11.55.png)

**Endpoints:** URL is http://jenkins.example.org/securityRealm/finishLogin, binding POST | **Proxy Endpoints:** unmodified
------------ | -------------
![](images/Screen_Shot_2015-12-10_at_16.11.57.png) | ![](images/Screen_Shot_2015-12-10_at_16.12.00.png)

**Notes:** unmodfied | **Advanced:** SHA-256
------------ | -------------
![](images/Screen_Shot_2015-12-10_at_16.12.02.png) | ![](images/Screen_Shot_2015-12-10_at_16.12.05.png)

Select the Relying Party Trust and click on Edit Claim Rules.... You should expose the following LDAP attributes: | -
------------ | -------------
![](images/Screen_Shot_2015-12-10_at_16.12.23.png) | ![](images/Screen_Shot_2015-12-10_at_16.12.27.png)

Allow all users to connect, or modify depending on your setup: | -
------------ | -------------
![](images/Screen_Shot_2015-12-10_at_16.12.36.png) | ![](images/Screen_Shot_2015-12-10_at_16.12.40.png)

**Delegation Authorization Rules:** unmodified	 

![](images/Screen_Shot_2015-12-10_at_16.12.45.png)


