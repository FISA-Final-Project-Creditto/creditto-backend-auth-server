package org.creditto.authserver.auth.jwk;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Optional;

@Service
public class JwkCacheService {

    private static final String JWK_CACHE_KEY = "jwk:set:cache";

    private final StringRedisTemplate redisTemplate;
    private final Duration cacheTtl;

    public JwkCacheService(
            StringRedisTemplate redisTemplate,
            @Value("${auth.jwk.cache-ttl:PT30M}") Duration cacheTtl
    ) {
        this.redisTemplate = redisTemplate;
        this.cacheTtl = cacheTtl != null ? cacheTtl : Duration.ofMinutes(30);
    }

    public Optional<String> getCachedJwk() {
        String value = redisTemplate.opsForValue().get(JWK_CACHE_KEY);
        return StringUtils.hasText(value)
                ? Optional.of(value)
                : Optional.empty();
    }

    public void cacheJwk(String jwkJson) {
        if (!StringUtils.hasText(jwkJson)) {
            return;
        }
        redisTemplate.opsForValue().set(JWK_CACHE_KEY, jwkJson, cacheTtl);
    }
}
