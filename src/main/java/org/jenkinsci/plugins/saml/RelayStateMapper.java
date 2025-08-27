package org.jenkinsci.plugins.saml;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.util.Optional;

/**
 * A filter for RelayState values used in SAML authentication.
 * Implementations can modify or validate the RelayState before it is used.
 */
public interface RelayStateMapper {
    @NonNull
    Optional<String> map(@NonNull String relayState);
}
