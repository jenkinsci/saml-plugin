package org.jenkinsci.plugins.saml.conf;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import java.util.Objects;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Class to configure SAML custom attributes to grab from the SAMLResponse and put in the User Profile.
 *
 * @author Kuisathaverat
 */
public class Attribute extends AttributeEntry {

    /**
     * Name of the attribute in the SAML Response.
     */
    private final String name;
    /**
     * Name to display as attribute's value label on the user profile.
     */
    private final String displayName;

    @SuppressWarnings("unused")
    @DataBoundConstructor
    public Attribute(String name, String displayName) {
        this.name = name;
        this.displayName = displayName;
    }

    public String getName() {
        return name;
    }

    public String getDisplayName() {
        return displayName;
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends Descriptor<AttributeEntry> {
        @NonNull
        @Override
        public String getDisplayName() {
            return "SAML Attribute";
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Attribute attribute = (Attribute) o;
        return Objects.equals(name, attribute.name) && Objects.equals(displayName, attribute.displayName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, displayName);
    }
}
