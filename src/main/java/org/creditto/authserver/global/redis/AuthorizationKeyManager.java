package org.creditto.authserver.global.redis;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.List;

import static org.creditto.authserver.global.redis.RedisConstants.*;

@Component
public class AuthorizationKeyManager {

    public String authorizationKey(String authorizationId) {
        return AUTHORIZATION_KEY_PREFIX + authorizationId;
    }

    public List<String> indexPrefixes() {
        return List.of(
                STATE_INDEX_PREFIX,
                AUTH_CODE_INDEX_PREFIX,
                ACCESS_TOKEN_INDEX_PREFIX,
                REFRESH_TOKEN_INDEX_PREFIX,
                OIDC_TOKEN_INDEX_PREFIX
        );
    }

    public String stateIndexKey(String state) {
        return buildIndexKey(STATE_INDEX_PREFIX, state);
    }

    public String authorizationCodeIndexKey(String code) {
        return buildIndexKey(AUTH_CODE_INDEX_PREFIX, code);
    }

    public String accessTokenIndexKey(String tokenValue) {
        return buildIndexKey(ACCESS_TOKEN_INDEX_PREFIX, tokenValue);
    }

    public String refreshTokenIndexKey(String tokenValue) {
        return buildIndexKey(REFRESH_TOKEN_INDEX_PREFIX, tokenValue);
    }

    public String oidcTokenIndexKey(String tokenValue) {
        return buildIndexKey(OIDC_TOKEN_INDEX_PREFIX, tokenValue);
    }

    private String buildIndexKey(String prefix, String value) {
        return StringUtils.hasText(value) ? prefix + value : null;
    }
}
