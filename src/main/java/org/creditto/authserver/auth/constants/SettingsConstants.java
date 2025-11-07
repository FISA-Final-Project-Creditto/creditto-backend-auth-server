package org.creditto.authserver.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class SettingsConstants {
    public static final String REQUIRE_AUTHORIZATION_CONSENT = "requireAuthorizationConsent";
    public static final String REQUIRE_PROOF_KEY = "requireProofKey";
    public static final String JWK_SET_URL = "jwkSetUrl";

    // TokenSettings
    public static final String ACCESS_TOKEN_TTL = "accessTokenTimeToLive";
    public static final String REFRESH_TOKEN_TTL = "refreshTokenTimeToLive";
    public static final String REUSE_REFRESH_TOKENS = "reuseRefreshTokens";
}
