package org.creditto.authserver.global.redis;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.time.Duration;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class RedisConstants {
    public static final String AUTHORIZATION_KEY_PREFIX = "oauth2:authorization:";
    public static final String STATE_INDEX_PREFIX = "oauth2:index:state:";
    public static final String AUTH_CODE_INDEX_PREFIX = "oauth2:index:code:";
    public static final String ACCESS_TOKEN_INDEX_PREFIX = "oauth2:index:access:";
    public static final String REFRESH_TOKEN_INDEX_PREFIX = "oauth2:index:refresh:";
    public static final String OIDC_TOKEN_INDEX_PREFIX = "oauth2:index:oidc:";
    public static final Duration MIN_TTL = Duration.ofSeconds(1);
}
