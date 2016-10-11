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
