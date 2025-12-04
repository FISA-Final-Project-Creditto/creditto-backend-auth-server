package org.creditto.authserver.global.redis;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.creditto.authserver.global.redis.RedisConstants.MIN_TTL;

@Component
public class AuthorizationTtlPolicy {

    private final Duration defaultAuthorizationTtl;

    public AuthorizationTtlPolicy(@Value("${auth.token.refresh-ttl:PT336H}") Duration defaultAuthorizationTtl) {
        this.defaultAuthorizationTtl = defaultAuthorizationTtl != null ? defaultAuthorizationTtl : Duration.ofDays(14);
    }

    public Duration authorizationTtl(OAuth2Authorization authorization) {
        Instant now = Instant.now();
        List<Instant> candidates = new ArrayList<>();
        candidates.add(extractExpiresAt(authorization.getToken(OAuth2AuthorizationCode.class)));
        candidates.add(extractExpiresAt(authorization.getToken(OAuth2AccessToken.class)));
        candidates.add(extractExpiresAt(authorization.getToken(OAuth2RefreshToken.class)));
        candidates.add(extractExpiresAt(authorization.getToken(OidcIdToken.class)));

        Instant max = candidates.stream()
                .filter(Objects::nonNull)
                .max(Instant::compareTo)
                .orElse(null);

        if (max == null) {
            return defaultAuthorizationTtl;
        }

        Duration ttl = Duration.between(now, max);
        return ensurePositive(ttl);
    }

    public Duration tokenTtl(Instant expiresAt) {
        if (expiresAt == null) {
            return defaultAuthorizationTtl;
        }
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        return ensurePositive(ttl);
    }

    public Duration ensurePositive(Duration ttl) {
        if (ttl == null || ttl.isNegative() || ttl.isZero()) {
            return MIN_TTL;
        }
        return ttl;
    }

    private Instant extractExpiresAt(OAuth2Authorization.Token<? extends OAuth2Token> token) {
        return token != null && token.getToken() != null ? token.getToken().getExpiresAt() : null;
    }
}
