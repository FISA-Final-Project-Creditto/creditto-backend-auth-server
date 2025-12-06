package org.creditto.authserver.domain.client.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.domain.client.entity.OAuth2AuthorizationEntity;
import org.creditto.authserver.global.redis.AuthorizationEntityMapper;
import org.creditto.authserver.global.redis.AuthorizationKeyManager;
import org.creditto.authserver.global.redis.AuthorizationRedisRepository;
import org.creditto.authserver.global.redis.AuthorizationTtlPolicy;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.function.UnaryOperator;

import static org.creditto.authserver.global.response.error.AssertErrorMessage.ID_EMPTY;
import static org.creditto.authserver.global.response.error.AssertErrorMessage.TOKEN_EMPTY;

@Slf4j
@Service
@RequiredArgsConstructor
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final AuthorizationRedisRepository redisRepository;
    private final AuthorizationEntityMapper authorizationEntityMapper;
    private final AuthorizationKeyManager keyManager;
    private final AuthorizationTtlPolicy ttlPolicy;

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");

        OAuth2AuthorizationEntity existingEntity = redisRepository.findAuthorization(authorization.getId());
        if (existingEntity != null) {
            OAuth2Authorization existingAuthorization = authorizationEntityMapper.toObject(existingEntity);
            removeIndexes(existingAuthorization);
        }

        OAuth2AuthorizationEntity entity = authorizationEntityMapper.toEntity(authorization, existingEntity);
        Duration ttl = ttlPolicy.authorizationTtl(authorization);
        redisRepository.saveAuthorization(entity, ttlPolicy.ensurePositive(ttl));
        registerIndexes(authorization, ttlPolicy.ensurePositive(ttl));

        log.debug("OAuth2Authorization Redis 저장 완료 - ID: {}, Principal: {}", authorization.getId(), authorization.getPrincipalName());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        OAuth2Authorization stored = findById(authorization.getId());
        if (stored != null) {
            removeIndexes(stored);
        }
        redisRepository.deleteAuthorization(authorization.getId());
        log.debug("OAuth2Authorization Redis 삭제 완료 - ID: {}", authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, ID_EMPTY);
        OAuth2AuthorizationEntity entity = redisRepository.findAuthorization(id);
        return entity != null ? authorizationEntityMapper.toObject(entity) : null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, TOKEN_EMPTY);

        String authorizationId = resolveAuthorizationId(token, tokenType);
        if (!StringUtils.hasText(authorizationId)) {
            return null;
        }
        return findById(authorizationId);
    }

    private String resolveAuthorizationId(String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            for (String prefix : keyManager.indexPrefixes()) {
                String id = redisRepository.readIndex(prefix + token);
                if (StringUtils.hasText(id)) {
                    return id;
                }
            }
            return null;
        }

        if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return redisRepository.readIndex(keyManager.accessTokenIndexKey(token));
        }
        if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return redisRepository.readIndex(keyManager.refreshTokenIndexKey(token));
        }
        if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return redisRepository.readIndex(keyManager.authorizationCodeIndexKey(token));
        }
        if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return redisRepository.readIndex(keyManager.stateIndexKey(token));
        }
        if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            return redisRepository.readIndex(keyManager.oidcTokenIndexKey(token));
        }
        return null;
    }

    private void registerIndexes(OAuth2Authorization authorization, Duration fallbackTtl) {
        storeIndex(keyManager.stateIndexKey(authorization.getAttribute(OAuth2ParameterNames.STATE)),
                authorization.getId(), fallbackTtl);

        storeTokenIndex(authorization.getToken(OAuth2AuthorizationCode.class),
                keyManager::authorizationCodeIndexKey,
                authorization.getId());

        storeTokenIndex(authorization.getToken(OAuth2AccessToken.class),
                keyManager::accessTokenIndexKey,
                authorization.getId());

        storeTokenIndex(authorization.getToken(OAuth2RefreshToken.class),
                keyManager::refreshTokenIndexKey,
                authorization.getId());

        storeTokenIndex(authorization.getToken(OidcIdToken.class),
                keyManager::oidcTokenIndexKey,
                authorization.getId());
    }

    private void removeIndexes(OAuth2Authorization authorization) {
        deleteIndex(keyManager.stateIndexKey(authorization.getAttribute(OAuth2ParameterNames.STATE)));
        deleteTokenIndex(authorization.getToken(OAuth2AuthorizationCode.class), keyManager::authorizationCodeIndexKey);
        deleteTokenIndex(authorization.getToken(OAuth2AccessToken.class), keyManager::accessTokenIndexKey);
        deleteTokenIndex(authorization.getToken(OAuth2RefreshToken.class), keyManager::refreshTokenIndexKey);
        deleteTokenIndex(authorization.getToken(OidcIdToken.class), keyManager::oidcTokenIndexKey);
    }

    private void storeIndex(String key, String authorizationId, Duration ttl) {
        if (!StringUtils.hasText(key)) {
            return;
        }
        redisRepository.storeIndex(key, authorizationId, ttlPolicy.ensurePositive(ttl));
    }

    private <T extends OAuth2Token> void storeTokenIndex(
            OAuth2Authorization.Token<T> token,
            UnaryOperator<String> keyFunction,
            String authorizationId
    ) {
        if (token == null || token.getToken() == null) {
            return;
        }
        String key = keyFunction.apply(token.getToken().getTokenValue());
        Duration ttl = ttlPolicy.tokenTtl(token.getToken().getExpiresAt());
        redisRepository.storeIndex(key, authorizationId, ttl);
    }

    private <T extends OAuth2Token> void deleteTokenIndex(
            OAuth2Authorization.Token<T> token,
            UnaryOperator<String> keyFunction
    ) {
        if (token == null || token.getToken() == null) {
            return;
        }
        String key = keyFunction.apply(token.getToken().getTokenValue());
        deleteIndex(key);
    }

    private void deleteIndex(String key) {
        if (StringUtils.hasText(key)) {
            redisRepository.deleteIndex(key);
        }
    }
}
