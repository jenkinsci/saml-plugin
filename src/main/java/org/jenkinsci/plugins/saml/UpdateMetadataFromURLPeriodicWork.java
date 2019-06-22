package org.jenkinsci.plugins.saml;

import hudson.Extension;
import hudson.model.AsyncAperiodicWork;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * <p>This periodic work update the IdP Metadata File, the periodicof the execution is defined on the SAML Plugin configuration.</p>
 * <p>If the Preriod is set to 0 the Periodic work is mostly disabled, it will check the changes on config
 * every 10 minutes to see if it is enabled again, if the period change it is re-enabled again.</p>
 */
@Extension
public class UpdateMetadataFromURLPeriodicWork extends AsyncAperiodicWork {
    private static final Logger LOG = Logger.getLogger(UpdateMetadataFromURLPeriodicWork.class.getName());
    /**
     * property to set the initial delay of the AsyncAperiodicWork.
     * -Dorg.jenkinsci.plugins.saml.UpdateMetadataFromURLPeriodicWork.initialDelay=MILLISECONDS
     */
    public static final String INITIAL_DELAY_PROPERTY = UpdateMetadataFromURLPeriodicWork.class.getName() + ".initialDelay";
    public static final long INITIAL_DELAY = Long.parseLong(System.getProperty(INITIAL_DELAY_PROPERTY, "10000"));

    /**
     * {@inheritDoc}
     */
    public UpdateMetadataFromURLPeriodicWork() {
        super("Update IdP Metadata from URL PeriodicWork");
    }

    /**
     * @return the configured period, if the configured period is 0 return 10 minutes,
     * if we are starting the Jenkins instance schedule an execution after 10 seconds.
     */
    @Override
    public long getRecurrencePeriod() {
        long ret = getConfiguredPeriod();
        if (ret == 0) {
            ret = TimeUnit.MINUTES.toMillis(10);
        }
        return ret;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public long getInitialDelay() {
        return INITIAL_DELAY;
    }

    /**
     * @return check the configured period in the SAML Plugin configuration.
     */
    private long getConfiguredPeriod() {
        long ret = 0;
        jenkins.model.Jenkins j = jenkins.model.Jenkins.get();
        if (j.getSecurityRealm() instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) j.getSecurityRealm();
            IdpMetadataConfiguration config = samlSecurityRealm.getIdpMetadataConfiguration();
            if(config != null && config.getPeriod() != null && StringUtils.isNotBlank(config.getUrl())) {
                ret = TimeUnit.MINUTES.toMillis(config.getPeriod());
            }
        }
        return ret;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public hudson.model.AperiodicWork getNewInstance() {
        return new UpdateMetadataFromURLPeriodicWork();
    }

    /**
     * {@inheritDoc}
     * <p>Connect to the URL configured on the SAML configuration to get the IdP Metadata, then download it </p>
     * <p>if the period configured is 0 it returns directly, do nothing.</p>
     */
    @Override
    protected void execute(hudson.model.TaskListener listener) {
        if (getConfiguredPeriod() == 0) {
            return;
        }

        Jenkins j = Jenkins.get();
        if (j.getSecurityRealm() instanceof SamlSecurityRealm) {
            SamlSecurityRealm samlSecurityRealm = (SamlSecurityRealm) j.getSecurityRealm();
            try {
                samlSecurityRealm.getIdpMetadataConfiguration().updateIdPMetadata();
            } catch (IOException | IllegalArgumentException e) {
                LOG.log(Level.SEVERE, e.getMessage(), e);
            }
        }
    }
}
