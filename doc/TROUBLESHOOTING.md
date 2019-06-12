Troubleshooting
----------------
When you face an issue you could try to enable a logger to these two packages on the level specified and try to find errors, this will show in logs the information send from Jenkins (SP) to the SAML service (IdP), this information could be sensitive so take care where you copy/send it.  

    * org.jenkinsci.plugins.saml - FINEST
    * org.pac4j - FINE
    
**If you have configured the Jenkins proxy setting, and you do not want to use the proxy to connect to your IdP you have to add your IdP to no-proxy hosts**
    
### IdP Metadata

The IdP metadata should looks like this one, the main data are the `entityID`, `IDPSSODescriptor` section, and `SingleSignOnService` the three sections are needed.

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<EntityDescriptor xmlns:xsi="https://www.w3.org/2001/XMLSchema-instance"
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://SAML_SERVER/idp/">
    <!-- The SSO service at the identity provider -->
    <IDPSSODescriptor WantAuthnRequestsSigned="false"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>sEqZ5xC8GFgcPcUOI6CnUYDnO630cAqHjLdVp82eaxFRr7F8j75Go7b/HiWcp87iOAzQ8NrCWUwYzny7mogvopNq2/oONqNXML4pM6v8epHWAZePBcW+o5tVJMYseAl7bwX/VE3Ro8LakHoBbDlRaiHT3A55p4Vyp0OZUGHLazrV9yCKvvDPU+pPocB4PKR3nBOQ9AyF0r1a8T8/y90X59BpHJxhXfJSgT8U/95KIV9+cEb11BApr5a3KrxIZAep6CC4C9MVmIsUSjpM6bOt4qqiQC9WVbD5i5ZnimiFYvHt/QOvyFT751T9QylWz2SGwzyqwG6+LZXswbeITjcrSZkdInkkWybqC+igvOrSOi6sSn5GjSHQqskCI6GwYNQ9ndAsWBwRdyx+ydZGVo0riZurc/YdhH13VpLnx6Vrk8+Sbf0oHqr7BSdSnl1bi/qptIg9ksF5Zw8Rkep9118A88w7uEEBO3q+fGfE72FYMxsp5k/MSLgKkwqlCpqzhmCd2L6ZU/g45sEQSwdaS9YzsY7o4kGrzSzCGxsinP/67UddiTFiJNan2zzVyeVUdKthbek5hHNord9durQXN8O4t5wlMFS+67+ReCs1g/S+eKJelvH5aPtbPE7lttt/hZ8LgKX2vGT5yFcQmT46Kj6u3tSbNGnipl4BQ1ItbQZoe1g=
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </KeyDescriptor>
    <!-- Supported Name Identifier Formats -->
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <!-- AuthenticationRequest Consumer endpoint -->
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://SAML_SERVER/idp"/>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://SAML_SERVER/idp"/>
</IDPSSODescriptor>
</EntityDescriptor>
```

### SAMLResponse

This is an example of SAMLResponse, it is the message sent by the IdP to Jenkins, it should contains an `Assertion` with signature details if it is supported by the IdP, a `Subject` with the request details, `Conditions` with the validity of the session, `AuthnStatement` with the session details, finally a `AttributeStatement` with the attributes sent by the IdP.

```
<Response
    xmlns="urn:oasis:names:tc:SAML:2.0:protocol"
    Destination="https://JENKINS_SERVER/securityRealm/finishLogin"
    ID="_c266abbff66bba8bcd763443655ea1c5861d"
    InResponseTo="_75a5cb8c9514c22751e05b29e698e0e8"
    IssueInstant="2016-04-18T19:04:53Z"
    Version="2.0">
    <ns1:Issuer xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"
        Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://SAML_SERVER/idp/</ns1:Issuer>
    <Status>
        <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </Status>
    <ns2:Assertion xmlns:ns2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_4d406d6505202232c48a50726c55d58f548c"            
        IssueInstant="2016-04-18T19:04:53Z" Version="2.0">
        <ns2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://SAML_SERVER/idp/</ns2:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#_4d406d6505202232c48a50726c55d58f548c">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>B+nZTeDSNSpigeyDg2475274242ARIw6ttEXHY3PMk=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>VTCuyYj09/CbuU7+pX6g3wjTlocTH83RkWEG6xy2t1ZSDPS0Q0gjfmh8/HMNSOoold9i2zY5Qi4/idZ7yKBe0nR7WDZDPkc3FSovvX73FThJEZ5aJk/6uhr5yUzj3qypA9bLsHdMO75SfaDzotb0c4mIBWLuPX245sZretx6pNRHDYntgQB9ikYC6UQPuSwn1+p/iq1B+GnbNp7m+og0rL5ooc7jPnpqiWBn2648ZCSsnoemrCiSmDVR90XJ7GFEz27W7BH8ZH49DdML6xmqiBvWmZC7LpfkcoF54mLZMdVYM=
            </ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>gpEQ4+mCQGMhwPtrqp1fPXpocgNZ9NkH/FZ62bzYTswVBF6VJPm5VuslmxGTVOMBd/qNKin/xlX2nL5J4mABXZ3OrUcyX//cwK3zqyS2Gn9LaAQnwOdkpXVQzeufCS0agrpfOtEKwWHgbs1m4Dfcl82SWOSbBZhLOUmtDMa0y1DqMB2nxVwJY8ULD+p3HUJGnGxx7JvGBo3OM/tZ3DC7zC0QGlPfuMFPT1GuKsdG11OZ1kWNa9XxQj8pOpPDuiBrxCJDz5vM00ThgnkORITYSkWPO05oe+RBms/qcfYH5JOiR5NJMxojAv2jqvAT8YES1l376yaHWEampzH1nWdW9XQvpr9l297yK7GxGU3Pj4M7ryalYXyH/5tqGFkcQQsX6TDUcmy4M6DlRTe3f7U3duEA1KlQApShDU7lYt41g8vv7pVFN14z9ZNhztJIErmkvR0H/QHR2SVg+WWM0Ql+rMzgsYVfPa4xCIpfEmiWujeeboJay+492k3Im5XbUUCG49UHigyoaAbLIwrCpnFLd3bGlAjun75WWbAHlaILkXAhTNMSPpbWBXrfhwgLwYK5zLGgkpsQPKzzAvQoLHT0wP0R1CbHWGmyNE45ArY3QK0BFb0IRxysNjYIu276JkDjxpdK93ofnWImwE9NLxWh/rqJ2IJ/+6dl8tnYVoT1adg=
                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <!-- User information -->
        <ns2:Subject>
            <ns2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">USER_NAME</ns2:NameID>
            <ns2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <ns2:SubjectConfirmationData InResponseTo="_75a5cb8c9514c22751e05b29e698e0e8" NotOnOrAfter="2016-04-18T19:06:23Z"   
                Recipient="https://JENKINS_SERVER/securityRealm/finishLogin"/>
            </ns2:SubjectConfirmation>
        </ns2:Subject>
        <!-- expiration of session -->
        <ns2:Conditions NotBefore="2016-04-18T19:04:23Z" NotOnOrAfter="2016-04-18T19:06:23Z">
            <ns2:AudienceRestriction>
                <ns2:Audience>https://JENKINS_SERVER/securityRealm/finishLogin</ns2:Audience>
            </ns2:AudienceRestriction>
        </ns2:Conditions>
        <ns2:AuthnStatement AuthnInstant="2016-04-18T19:04:53Z" SessionIndex="/47O5ynZIyr+2365762LqnEmAZs=JI+mPg=="
            SessionNotOnOrAfter="2016-04-18T19:06:23Z">
            <ns2:AuthnContext>
                <ns2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</ns2:AuthnContextClassRef>
                </ns2:AuthnContext>
        </ns2:AuthnStatement>
        <!-- Authorization Groups -->
        <ns2:AttributeStatement>
            <ns2:Attribute name="groups">
                <ns2:AttributeValue>groupOne</ns2:AttributeValue>
                <ns2:AttributeValue>groupTwo</ns2:AttributeValue>
                <ns2:AttributeValue>groupThree</ns2:AttributeValue>                       
            </ns2:Attribute>
        </ns2:AttributeStatement>
    </ns2:Assertion>
</Response>
```

### SAMLException: Identity provider has no single sign on service available for the selected

You have to check your IdP metadata contains the section `SingleSignOnService`

```
org.pac4j.saml.exceptions.SAMLException: Identity provider has no single sign on service available for the selected profileorg.opensaml.saml.saml2.metadata.impl.IDPSSODescriptorImpl@628767f5
	at org.pac4j.saml.context.SAML2MessageContext.getIDPSingleSignOnService(SAML2MessageContext.java:93)
```

### Azure AD

After leaving the system for some period of time (like overnight) and trying to log in again you get this error

```
org.pac4j.saml.exceptions.SAMLException: No valid subject assertion found in response 
at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validateSamlSSOResponse(SAML2DefaultResponseValidator.java:313) 
at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validate(SAML2DefaultResponseValidator.java:138) 
at org.pac4j.saml.sso.impl.SAML2WebSSOMessageReceiver.receiveMessage(SAML2WebSSOMessageReceiver.java:77) 
at org.pac4j.saml.sso.impl.SAML2WebSSOProfileHandler.receive(SAML2WebSSOProfileHandler.java:35) 
at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:225) 
at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:60) 
at org.pac4j.core.client.IndirectClient.getCredentials(IndirectClient.java:106) 
at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:53) 
at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:33) 
at org.jenkinsci.plugins.saml.OpenSAMLWrapper.get(OpenSAMLWrapper.java:65) 
at org.jenkinsci.plugins.saml.SamlSecurityRealm.doFinishLogin(SamlSecurityRealm.java:265) 
at java.lang.invoke.MethodHandle.invokeWithArguments(MethodHandle.java:627) 
at org.kohsuke.stapler.Function$MethodFunction.invoke(Function.java:343) 
at org.kohsuke.stapler.Function.bindAndInvoke(Function.java:184) 
at org.kohsuke.stapler.Function.bindAndInvokeAndServeResponse(Function.java:117) 
at org.kohsuke.stapler.MetaClass$1.doDispatch(MetaClass.java:129) 
at org.kohsuke.stapler.NameBasedDispatcher.dispatch(NameBasedDispatcher.java:58) 
at org.kohsuke.stapler.Stapler.tryInvoke(Stapler.java:715) 
Caused: javax.servlet.ServletException at org.kohsuke.stapler.Stapler.tryInvoke(Stapler.java:765) 

...
at winstone.BoundedExecutorService$1.run(BoundedExecutorService.java:77) 
at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149) 
at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624) 
at java.lang.Thread.run(Thread.java:748)
```
* Click on logout button, then hit the Jenkins sign-in again.
* Clear the cookies in your browser or Go to Azure and sign out of the user name, then hit the Jenkins sign-in again.
* The max lifetime of the Access Token in Azure AD seems to be 24 hours where the refresh token can live for a maximum of 14 days (if the access token expires the refresh token is used to try to obtain a new access token).  The Jenkins setting in Configure Global Security > SAML Identity Provider Settings > Maximum Authentication Lifetime is 24 hours (86400 in seconds) upping this to 1209600 (which is 14 days in seconds/the max lifetime of the Refresh Token).
* Enable the advanced "force authentication" setting is another workaround.
 

### Identity provider has no single sign on service available for the selected...

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

### Identity provider does not support encryption settings

* Check the encryption methods, signing methods, and keys types supported by your IdP and set the encryption settings correctly  
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

### The SAMLResponse is not correct bsae64 encode

The SAMLResponse message is not valid because the `SAMLResponse` value is not in Base64 format or it is corrupted.

```
Caused by: java.lang.IllegalStateException: org.pac4j.saml.exceptions.SAMLException: Error decoding saml message
	at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:68)
	at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:39)
	at org.jenkinsci.plugins.saml.OpenSAMLWrapper.get(OpenSAMLWrapper.java:65)
	at org.jenkinsci.plugins.saml.SamlSecurityRealm.doFinishLogin(SamlSecurityRealm.java:272)
	at java.lang.invoke.MethodHandle.invokeWithArguments(MethodHandle.java:627)
	at org.kohsuke.stapler.Function$MethodFunction.invoke(Function.java:343)
	... 77 more
```

### There is no SAMLResponse parameter in the POST message

The response message should have a parameter named `SAMLResponse` that should be the XML of the SAMLResponse in Base64 format.

```
Caused by: org.opensaml.messaging.decoder.MessageDecodingException: Request did not contain either a SAMLRequest or SAMLResponse parameter. Invalid request for SAML 2 HTTP POST binding.
	at org.pac4j.saml.transport.Pac4jHTTPPostDecoder.getBase64DecodedMessage(Pac4jHTTPPostDecoder.java:80)
	at org.pac4j.saml.transport.Pac4jHTTPPostDecoder.doDecode(Pac4jHTTPPostDecoder.java:62)
	at org.opensaml.messaging.decoder.AbstractMessageDecoder.decode(AbstractMessageDecoder.java:58)
	at org.pac4j.saml.sso.impl.SAML2WebSSOMessageReceiver.receiveMessage(SAML2WebSSOMessageReceiver.java:40)
	... 87 more
```

### No valid subject assertion found in response

Check that the `SP Entry ID` it is the same in the SP (Jenkins) and IdP, by default Jenkins uses `JENKINS_URL/securityRealm/finishLogin` you can change this value if you use the SAML Plugin's Advanced Setting named "SP Entity ID".

```
org.pac4j.saml.exceptions.SAMLException: No valid subject assertion found in response 
at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validateSamlSSOResponse(SAML2DefaultResponseValidator.java:313) 
at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validate(SAML2DefaultResponseValidator.java:138) 
at org.pac4j.saml.sso.impl.SAML2WebSSOMessageReceiver.receiveMessage(SAML2WebSSOMessageReceiver.java:77) 
at org.pac4j.saml.sso.impl.SAML2WebSSOProfileHandler.receive(SAML2WebSSOProfileHandler.java:35) 
at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:225) 
at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:60) 
at org.pac4j.core.client.IndirectClient.getCredentials(IndirectClient.java:106) 
at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:53) 
at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:33) 
at org.jenkinsci.plugins.saml.OpenSAMLWrapper.get(OpenSAMLWrapper.java:65) 
at org.jenkinsci.plugins.saml.SamlSecurityRealm.doFinishLogin(SamlSecurityRealm.java:265) 
at java.lang.invoke.MethodHandle.invokeWithArguments(MethodHandle.java:627) 
at org.kohsuke.stapler.Function$MethodFunction.invoke(Function.java:343) 
at org.kohsuke.stapler.Function.bindAndInvoke(Function.java:184) 
at org.kohsuke.stapler.Function.bindAndInvokeAndServeResponse(Function.java:117) 
at org.kohsuke.stapler.MetaClass$1.doDispatch(MetaClass.java:129) 
at org.kohsuke.stapler.NameBasedDispatcher.dispatch(NameBasedDispatcher.java:58) 
at org.kohsuke.stapler.Stapler.tryInvoke(Stapler.java:715) 
Caused: javax.servlet.ServletException at org.kohsuke.stapler.Stapler.tryInvoke(Stapler.java:765) 

...
at winstone.BoundedExecutorService$1.run(BoundedExecutorService.java:77) 
at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149) 
at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624) 
at java.lang.Thread.run(Thread.java:748)
```
### Authentication issue instant is too old or in the future

You should check that your `Maximum Authentication Lifetime` setting is the same that your Idp has, if Jenkins has a lower value you will see this error. The solution is to set `Maximum Authentication Lifetime` to your token validity. Another workaround is to set `Advanced Configuration/Force Authentication` but this will as for login everytime the session expires.

```
Oct 26, 2018 9:08:44 PM org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator validateSamlSSOResponse
SEVERE: Current assertion validation failed, continue with the next oneorg.pac4j.saml.exceptions.SAMLException: Authentication issue instant is too old or in the future
  at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validateAuthenticationStatements(SAML2DefaultResponseValidator.java:620)
  at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validateAssertion(SAML2DefaultResponseValidator.java:393)
  at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validateSamlSSOResponse(SAML2DefaultResponseValidator.java:302)
  at org.pac4j.saml.sso.impl.SAML2DefaultResponseValidator.validate(SAML2DefaultResponseValidator.java:138)
  at org.pac4j.saml.sso.impl.SAML2WebSSOMessageReceiver.receiveMessage(SAML2WebSSOMessageReceiver.java:77)
  at org.pac4j.saml.sso.impl.SAML2WebSSOProfileHandler.receive(SAML2WebSSOProfileHandler.java:35)
  at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:225)
  at org.pac4j.saml.client.SAML2Client.retrieveCredentials(SAML2Client.java:60)
  at org.pac4j.core.client.IndirectClient.getCredentials(IndirectClient.java:106)
  at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:55)
  at org.jenkinsci.plugins.saml.SamlProfileWrapper.process(SamlProfileWrapper.java:35)
  at org.jenkinsci.plugins.saml.OpenSAMLWrapper.get(OpenSAMLWrapper.java:64)
  at org.jenkinsci.plugins.saml.SamlSecurityRealm.doFinishLogin(SamlSecurityRealm.java:304)
....
  at org.eclipse.jetty.server.HttpChannel.handle(HttpChannel.java:352)
  at org.eclipse.jetty.server.HttpConnection.onFillable(HttpConnection.java:260)
  at org.eclipse.jetty.io.AbstractConnection$ReadCallback.succeeded(AbstractConnection.java:281)
  at org.eclipse.jetty.io.FillInterest.fillable(FillInterest.java:102)
  at org.eclipse.jetty.io.ChannelEndPoint$2.run(ChannelEndPoint.java:118)
  at org.eclipse.jetty.util.thread.strategy.EatWhatYouKill.runTask(EatWhatYouKill.java:333)
  at org.eclipse.jetty.util.thread.strategy.EatWhatYouKill.doProduce(EatWhatYouKill.java:310)
  at org.eclipse.jetty.util.thread.strategy.EatWhatYouKill.tryProduce(EatWhatYouKill.java:168)
  at org.eclipse.jetty.util.thread.strategy.EatWhatYouKill.run(EatWhatYouKill.java:126)
  at org.eclipse.jetty.util.thread.ReservedThreadExecutor$ReservedThread.run(ReservedThreadExecutor.java:366)
  at org.eclipse.jetty.util.thread.QueuedThreadPool.runJob(QueuedThreadPool.java:762)
  at org.eclipse.jetty.util.thread.QueuedThreadPool$2.run(QueuedThreadPool.java:680)
  at java.lang.Thread.run(Thread.java:748)
```
