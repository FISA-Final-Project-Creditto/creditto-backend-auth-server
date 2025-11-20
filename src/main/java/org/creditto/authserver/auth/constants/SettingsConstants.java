package org.creditto.authserver.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SettingsConstants {
    public static final String REQUIRE_AUTHORIZATION_CONSENT = "requireAuthorizationConsent";
    public static final String REQUIRE_PROOF_KEY = "requireProofKey";
    public static final String JWK_SET_URL = "jwkSetUrl";

    // TokenSettings
    public static final String ACCESS_TOKEN_TTL = "settings.token.access-token-time-to-live";
    public static final String LEGACY_ACCESS_TOKEN_TTL = "accessTokenTimeToLive";
    public static final String REFRESH_TOKEN_TTL = "settings.token.refresh-token-time-to-live";
    public static final String LEGACY_REFRESH_TOKEN_TTL = "refreshTokenTimeToLive";
    public static final String REUSE_REFRESH_TOKENS = "settings.token.reuse-refresh-tokens";
    public static final String LEGACY_REUSE_REFRESH_TOKENS = "reuseRefreshTokens";
}
