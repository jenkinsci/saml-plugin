Jenkins SAML Plugin
===================

A SAML 2.0 Plugin for the Jenkins Continuous Integration server

Usage
-------------------
See the [SAML Plugin page on the Jenkins wiki](https://wiki.jenkins-ci.org/display/JENKINS/SAML+Plugin)

Local development
-------------------

Run `mvn hpi:run` and visit http://localhost:8080/jenkins/.
You will see the plugin under the "Installed" tab in the Jenkins plugin manager.

Releasing
-------------------

Create `~/.m2/settings.xml` per [plugin tutorial](https://wiki.jenkins-ci.org/display/JENKINS/Plugin+tutorial) and include password as described in [hosting plugins](https://wiki.jenkins-ci.org/display/JENKINS/Hosting+Plugins).
Run `mvn release:prepare release:perform`

Reporting issues
----------------
Check first is your issue in [open issues](https://issues.jenkins-ci.org/browse/JENKINS-38625?jql=project%20%3D%20JENKINS%20AND%20status%20in%20(Open%2C%20%22In%20Progress%22%2C%20Reopened%2C%20%22In%20Review%22)%20AND%20component%20%3D%20saml-plugin).
Report new issue on https://issues.jenkins-ci.org on component **saml-plugin**.

[How to report an issue](https://wiki.jenkins.io/display/JENKINS/How+to+report+an+issue)

**The Jenkins JIRA is not a support site. If you need assistance or have general questions, visit us [in chat](http://jenkins-ci.org/content/chat), or email one of the [mailing lists](http://jenkins-ci.org/content/mailing-lists).**

Changelog
-------------------
[Changelog](CHANGELOG.md)

Troubleshooting
----------------
When you face an issue you could try to enable a logger to these two packages on the level specified and try to find errors, this will show in logs the information send from Jenkins (SP) to the SAML service (IdP), this information could be sensitive so take care where you copy/send it.  

    * org.jenkinsci.plugins.saml - FINEST
    * org.pac4j - FINE


**Identity provider has no single sign on service available for the selected...**

* Check the SP EntryID configured on the IdP
* Check the binding methods supported on your IdP

```
org.pac4j.saml.exceptions.SAMLException: Identity provider has no single sign on service available for the selected profileorg.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorImpl@7ef38e46
	at org.pac4j.saml.context.SAML2MessageContext.getIDPSingleSignOnService(SAML2MessageContext.java:93)
	at org.pac4j.saml.sso.impl.SAML2AuthnRequestBuilder.build(SAML2AuthnRequestBuilder.java:70)
	at org.pac4j.saml.sso.impl.SAML2AuthnRequestBuilder.build(SAML2AuthnRequestBuilder.java:34)
	at org.pac4j.saml.client.SAML2Client.retrieveRedirectAction(SAML2Client.java:209)
	at org.pac4j.core.client.IndirectClient.getRedirectAction(IndirectClient.java:79)
	at org.jenkinsci.plugins.saml.SamlRedirectActionWrapper.process(SamlRedirectActionWrapper.java:47)
	at org.jenkinsci.plugins.saml.SamlRedirectActionWrapper.process(SamlRedirectActionWrapper.java:30)
	at org.jenkinsci.plugins.saml.OpenSAMLWrapper.get(OpenSAMLWrapper.java:65)
	at org.jenkinsci.plugins.saml.SamlSecurityRealm.doCommenceLogin(SamlSecurityRealm.java:260)
	at java.lang.invoke.MethodHandle.invokeWithArguments(MethodHandle.java:627)
	at org.kohsuke.stapler.Function$MethodFunction.invoke(Function.java:343)
	at org.kohsuke.stapler.Function.bindAndInvoke(Function.java:184)
	at org.kohsuke.stapler.Function.bindAndInvokeAndServeResponse(Function.java:117)
	at org.kohsuke.stapler.MetaClass$1.doDispatch(MetaClass.java:129)
	at org.kohsuke.stapler.NameBasedDispatcher.dispatch(NameBasedDispatcher.java:58)
	at org.kohsuke.stapler.Stapler.tryInvoke(Stapler.java:715)
```

**Identity provider does not support encryption settings**

* Downgrade to 0.14 version, if it works, then enable encryption on that version to be sure that this is the issue
* Check the JDK version does not have issues like this [JDK-8176043](https://bugs.openjdk.java.net/browse/JDK-8176043)

```
2017-10-18 20:26:49.568+0000 [id=1296]	WARNING	o.j.p.s.SuppressionFilter#reportError: Request processing failed. URI=/securityRealm/finishLogin clientIP=192.168.1.100 ErrorID=b04ec3d5-8fbe-4961-88f2-187f47649000
org.opensaml.messaging.decoder.MessageDecodingException: This message decoder only supports the HTTP POST method
	at org.pac4j.saml.transport.Pac4jHTTPPostDecoder.doDecode(Pac4jHTTPPostDecoder.java:57)
	at org.opensaml.messaging.decoder.AbstractMessageDecoder.decode(AbstractMessageDecoder.java:58)
	at org.pac4j.saml.sso.impl.SAML2WebSSOMessageReceiver.receiveMessage(SAML2WebSSOMessageReceiver.java:40)
Caused: org.pac4j.saml.exceptions.SAMLException: Error decoding saml message
	at org.pac4j.saml.sso.impl.SAML2WebSSOMessageReceiver.receiveMessage(SAML2WebSSOMessageReceiver.java:43)
	at org.pac4j.saml.sso.impl.SAML2WebSSOProfileHandler.receive(SAML2WebSSOProfileHandler.java:35)
	at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:225)
	at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:60)
	at org.pac4j.core.client.IndirectClient.getCredentials(IndirectClient.java:106)
	at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:53)
```

```
Caused by: java.lang.IllegalArgumentException: Illegal base64 character d
    at java.util.Base64$Decoder.decode0(Base64.java:714)
    at java.util.Base64$Decoder.decode(Base64.java:526)
    at java.util.Base64$Decoder.decode(Base64.java:549)
    at org.jenkinsci.plugins.saml.SamlSecurityRealm.doFinishLogin(SamlSecurityRealm.java:258)
```

