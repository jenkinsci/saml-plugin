Jenkins SAML Plugin
===================

A SAML 2.0 Plugin for the Jenkins Continuous Integration server

Changelog
-------------------
* For 1.1.3 and newer versions, see [GitHub Releases](https://github.com/jenkinsci/saml-plugin/releases)
* For previous versions, see [this file](./CHANGELOG.md)

Configure
-------------------
[Overall Configurarion](doc/CONFIGURE.md)

[ADFS Example](doc/ADFS_CONFIG.md)

[Azure Example](doc/CONFIGURE_AZURE.md)

Troubleshooting
-------------------
[Troubleshooting](doc/TROUBLESHOOTING.md)

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
Check first is your issue in [open issues](https://issues.jenkins-ci.org/issues/?jql=project%20%3D%20JENKINS%20AND%20resolution%20%3D%20Unresolved%20AND%20component%20%3D%20saml-plugin).
Report new issue on https://issues.jenkins-ci.org on component **saml-plugin**.

[How to report an issue](https://wiki.jenkins.io/display/JENKINS/How+to+report+an+issue)

**The Jenkins JIRA is not a support site. If you need assistance or have general questions, visit us [in chat](http://jenkins-ci.org/content/chat), or email one of the [mailing lists](http://jenkins-ci.org/content/mailing-lists).**


