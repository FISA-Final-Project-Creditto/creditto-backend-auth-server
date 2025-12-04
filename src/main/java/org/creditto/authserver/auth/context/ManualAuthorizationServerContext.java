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
        this(resolveIssuer(authorizationServerSettings), authorizationServerSettings);
    }

    private static String resolveIssuer(AuthorizationServerSettings settings) {
        return settings.getIssuer();
    }

    @Override
    public String getIssuer() {
        return resolveIssuer(authorizationServerSettings);
    }

    @Override
    public AuthorizationServerSettings getAuthorizationServerSettings() {
        return authorizationServerSettings;
    }
}
