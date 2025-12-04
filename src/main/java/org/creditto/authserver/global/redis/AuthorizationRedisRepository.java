package org.creditto.authserver.global.redis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.RequiredArgsConstructor;
import org.creditto.authserver.client.entity.OAuth2AuthorizationEntity;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class AuthorizationRedisRepository {

    private final StringRedisTemplate redisTemplate;
    private final AuthorizationKeyManager keyManager;
    private final ObjectMapper entityObjectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    public void saveAuthorization(OAuth2AuthorizationEntity entity, Duration ttl) {
        redisTemplate.opsForValue().set(
                keyManager.authorizationKey(entity.getId()),
                writeEntity(entity),
                ttl
        );
    }

    public OAuth2AuthorizationEntity findAuthorization(String authorizationId) {
        String json = redisTemplate.opsForValue().get(keyManager.authorizationKey(authorizationId));
        if (!StringUtils.hasText(json)) {
            return null;
        }
        try {
            return entityObjectMapper.readValue(json, OAuth2AuthorizationEntity.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("Authorization entity 역직렬화에 실패했습니다.", e);
        }
    }

    public void deleteAuthorization(String authorizationId) {
        redisTemplate.delete(keyManager.authorizationKey(authorizationId));
    }

    public void storeIndex(String indexKey, String authorizationId, Duration ttl) {
        if (!StringUtils.hasText(indexKey)) {
            return;
        }
        redisTemplate.opsForValue().set(indexKey, authorizationId, ttl);
    }

    public String readIndex(String indexKey) {
        return StringUtils.hasText(indexKey)
                ? redisTemplate.opsForValue().get(indexKey)
                : null;
    }

    public void deleteIndex(String indexKey) {
        if (StringUtils.hasText(indexKey)) {
            redisTemplate.delete(indexKey);
        }
    }

    private String writeEntity(OAuth2AuthorizationEntity entity) {
        try {
            return entityObjectMapper.writeValueAsString(entity);
        } catch (Exception e) {
            throw new IllegalArgumentException("Authorization entity 직렬화에 실패했습니다.", e);
        }
    }
}
