# Configure Keycloak

*Note:* replace https://keycloak.example.com with the root URL of your Keycloak service, replace jenkins.example.com with the name of your Jenkins host.

## Retrieve Jenkins Service Provider metadata

1. Choose SAML 2.0 as a Security Realm
2. Set the `IdP Metadata URL` to `https://keycloak.example.com/realms/{realm}/protocol/saml/descriptor`, where `{realm}` is the Realm of your client
3. Set the `Refresh Period` to `1440` (24h, suggested value)
4. Click `Validate IdP Metadata` to make sure metadata can be fetched
5. Click `Apply`
6. Find `Service Provider Metadata` link and save it as an XML file, e.g., `jenkins-sp-metadata.xml`

## Import a new client into Keycloak realm

[Using an entity descriptor to create a client](https://www.keycloak.org/docs/latest/server_admin/index.html#proc-using-an-entity-descriptors_server_administration_guide) is the reference documentation.

In a different tab in the Keycloak admin interface:

1. On the `Clients` page of the same realm as above chose to `Import client`
2. Select above `jenkins-sp-metadata.xml` as your `Resource file`
3. (Optional) Give a meaningful Name and Description
4. Save
5. Find "Name ID format" field and change to `username` or `persistent`
6. Save your change

## Add predefined mappers with user details

In the client details of the newly imported client:

1. Switch to `Client scopes`
2. Open a `dedicated` client scope
3. `Add predefined mappers`
4. Choose `X500 email`, `X500 givenName`, `X500 surname` and click `Add`
5. Open the newly added `X500 email` mapper and note the `SAML Attribute Name`, e.g., `urn:oid:1.2.840.113549.1.9.1`
6. Repeat previous step for given name or surname depending on your preference of Display Name on the jenkins side, e.g., `urn:oid:2.5.4.42` for given name. 
7. For the sake of an example we will use a predefined `Role list` mapper as a source of groups (`SAML Attribute Name` is `Role`). However, depending on your use case one more mapper might be needed to share group membership with Jenkins.

## Complete SAML 2.0 Security Realm configuration

Back on the Jenkins Security page:

1. Set "Email Attribute" to the value noted in step 5 above
2. Set "Display Name Attribute" to the value noted in step 6 above
3. Set "Group Attribute" to the value noted in step 7 above
4. "Save"

Test the authentication in an Incognito Window or a different browser.

For more details about the SAML Plugin configuration take a look at [Configuration Guide](CONFIGURE.md)
For troubleshooting steps and know issue see [Troubleshooting](TROUBLESHOOTING.md)
