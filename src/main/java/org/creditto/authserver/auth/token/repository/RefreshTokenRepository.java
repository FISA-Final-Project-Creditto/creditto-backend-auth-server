package org.creditto.authserver.auth.token.repository;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.token.domain.RefreshTokenSession;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Slf4j
@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {

    private static final String SESSION_KEY = "RT:%s:%s";
    private static final String TOKEN_INDEX_KEY = "RTI:%s";
    private static final Duration MIN_TTL = Duration.ofSeconds(1);

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    public void save(RefreshTokenSession session) {
        Duration ttl = calculateTtl(session.expiresAt());
        String sessionKey = buildSessionKey(session.userId(), session.sessionId());
        try {
            String json = objectMapper.writeValueAsString(session);
            redisTemplate.opsForValue().set(sessionKey, json, ttl);
            redisTemplate.opsForValue().set(buildTokenIndexKey(session.tokenValue()), sessionKey, ttl);
        } catch (Exception e) {
            log.error("RefreshTokenSession 직렬화 실패 - userId: {}", session.userId(), e);
            throw new IllegalStateException("RefreshTokenSession 직렬화에 실패했습니다.", e);
        }
    }

    public Optional<RefreshTokenSession> findByToken(String refreshToken) {
        String sessionKey = redisTemplate.opsForValue().get(buildTokenIndexKey(refreshToken));
        if (!StringUtils.hasText(sessionKey)) {
            return Optional.empty();
        }
        String json = redisTemplate.opsForValue().get(sessionKey);
        if (!StringUtils.hasText(json)) {
            return Optional.empty();
        }
        try {
            return Optional.of(objectMapper.readValue(json, RefreshTokenSession.class));
        } catch (Exception e) {
            log.error("RefreshTokenSession 역직렬화 실패 - key: {}", sessionKey, e);
            throw new IllegalStateException("RefreshTokenSession 역직렬화에 실패했습니다.", e);
        }
    }

    public void deleteByToken(String refreshToken) {
        String sessionKey = redisTemplate.opsForValue().get(buildTokenIndexKey(refreshToken));
        if (!StringUtils.hasText(sessionKey)) {
            return;
        }
        redisTemplate.delete(sessionKey);
        redisTemplate.delete(buildTokenIndexKey(refreshToken));
    }

    private Duration calculateTtl(Instant expiresAt) {
        if (expiresAt == null) {
            return MIN_TTL;
        }
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            return MIN_TTL;
        }
        return ttl;
    }

    private String buildSessionKey(String userId, String sessionId) {
        return SESSION_KEY.formatted(userId, sessionId);
    }

    private String buildTokenIndexKey(String tokenValue) {
        return TOKEN_INDEX_KEY.formatted(tokenValue);
    }
}
