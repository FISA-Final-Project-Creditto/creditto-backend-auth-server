package org.creditto.authserver.auth.context;

import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Simple AuthorizationServerContext implementation for manual token issuance.
 */
public record ManualAuthorizationServerContext(
        String issuer,
        AuthorizationServerSettings authorizationServerSettings
) implements AuthorizationServerContext {

    public ManualAuthorizationServerContext(AuthorizationServerSettings authorizationServerSettings) {
        this(authorizationServerSettings.getIssuer(), authorizationServerSettings);
    }

    @Override
    public String getIssuer() {
        return authorizationServerSettings.getIssuer();
    }

    @Override
    public AuthorizationServerSettings getAuthorizationServerSettings() {
        return authorizationServerSettings;
    }
}
