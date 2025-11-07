package org.creditto.authserver.client.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.client.entity.OAuth2AuthorizationEntity;
import org.creditto.authserver.client.repository.OAuth2AuthorizationRepository;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.creditto.authserver.global.response.error.AssertErrorMessage.*;

/**
 * JPA 기반 OAuth2AuthorizationService 구현
 * OAuth2Authorization을 데이터베이스에 저장/조회
 */
@Slf4j
@Service
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JpaOAuth2AuthorizationService(
            OAuth2AuthorizationRepository authorizationRepository,
            RegisteredClientRepository registeredClientRepository
    ) {
        Assert.notNull(authorizationRepository, AUTHORIZATION_REPOSITORY_NULL);
        Assert.notNull(registeredClientRepository, REGISTERED_CLIENT_REPOSITORY_NULL);
        this.authorizationRepository = authorizationRepository;
        this.registeredClientRepository = registeredClientRepository;

        // Jackson 모듈 등록
        ClassLoader classLoader = JpaOAuth2AuthorizationService.class.getClassLoader();
        List<com.fasterxml.jackson.databind.Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, AUTHORIZATION_NULL);

        OAuth2AuthorizationEntity entity = authorizationRepository.findById(authorization.getId())
                .orElse(OAuth2AuthorizationEntity.create(
                        authorization.getId(),
                        authorization.getRegisteredClientId(),
                        authorization.getPrincipalName(),
                        authorization.getAuthorizationGrantType().getValue()
                ));

        OAuth2AuthorizationEntity updatedEntity = toEntity(authorization, entity);
        authorizationRepository.save(updatedEntity);

        log.debug("OAuth2Authorization 저장 완료 - ID: {}, Principal: {}", authorization.getId(), authorization.getPrincipalName());
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, AUTHORIZATION_NULL);
        authorizationRepository.deleteById(authorization.getId());
        log.debug("OAuth2Authorization 삭제 완료 - ID: {}", authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, ID_EMPTY);
        return authorizationRepository.findById(id)
                .map(this::toObject)
                .orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, TOKEN_EMPTY);

        OAuth2AuthorizationEntity entity = null;

        if (tokenType == null) {
            entity = authorizationRepository
                    .findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(token)
                    .orElse(null);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            entity = authorizationRepository.findByState(token).orElse(null);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            entity = authorizationRepository.findByAuthorizationCodeValue(token).orElse(null);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            entity = authorizationRepository.findByAccessTokenValue(token).orElse(null);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            entity = authorizationRepository.findByRefreshTokenValue(token).orElse(null);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            entity = authorizationRepository.findByUserCodeValue(token).orElse(null);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            entity = authorizationRepository.findByDeviceCodeValue(token).orElse(null);
        }

        return entity != null ? toObject(entity) : null;
    }

    /**
     * Entity를 OAuth2Authorization 객체로 변환
     */
    private OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
        RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            throw new DataRetrievalFailureException(REGISTERED_CLIENT_NOT_FOUND_IN_REPO);
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
                .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));

        // Authorization Code
        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    entity.getAuthorizationCodeIssuedAt(),
                    entity.getAuthorizationCodeExpiresAt()
            );
            builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
        }

        // Access Token
        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes())
            );
            builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
        }

        // Refresh Token
        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt()
            );
            builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
        }

        // OIDC ID Token
        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    entity.getOidcIdTokenIssuedAt(),
                    entity.getOidcIdTokenExpiresAt(),
                    parseMap(entity.getOidcIdTokenClaims())
            );
            builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
        }

        return builder.build();
    }

    /**
     * OAuth2Authorization을 Entity로 변환
     */
    private OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization, OAuth2AuthorizationEntity existingEntity) {
        // 기본 정보로 Builder 생성
        OAuth2AuthorizationEntity.OAuth2AuthorizationEntityBuilder builder = OAuth2AuthorizationEntity.builder()
                .id(authorization.getId())
                .registeredClientId(authorization.getRegisteredClientId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
                .authorizedScopes(StringUtils.collectionToCommaDelimitedString(authorization.getAuthorizedScopes()))
                .attributes(writeMap(authorization.getAttributes()))
                .state(authorization.getAttribute(OAuth2ParameterNames.STATE));

        // 기존 엔티티가 있으면 createdAt 유지
        if (existingEntity != null && existingEntity.getCreatedAt() != null) {
            builder.createdAt(existingEntity.getCreatedAt());
        }

        // Authorization Code
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        setTokenValues(
                authorizationCode,
                builder::authorizationCodeValue,
                builder::authorizationCodeIssuedAt,
                builder::authorizationCodeExpiresAt,
                builder::authorizationCodeMetadata
        );

        // Access Token
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        setTokenValues(
                accessToken,
                builder::accessTokenValue,
                builder::accessTokenIssuedAt,
                builder::accessTokenExpiresAt,
                builder::accessTokenMetadata
        );
        if (accessToken != null && accessToken.getToken().getScopes() != null) {
            builder.accessTokenType(accessToken.getToken().getTokenType().getValue());
            builder.accessTokenScopes(StringUtils.collectionToCommaDelimitedString(accessToken.getToken().getScopes()));
        }

        // Refresh Token
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        setTokenValues(
                refreshToken,
                builder::refreshTokenValue,
                builder::refreshTokenIssuedAt,
                builder::refreshTokenExpiresAt,
                builder::refreshTokenMetadata
        );

        // OIDC ID Token
        OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
                authorization.getToken(OidcIdToken.class);
        setTokenValues(
                oidcIdToken,
                builder::oidcIdTokenValue,
                builder::oidcIdTokenIssuedAt,
                builder::oidcIdTokenExpiresAt,
                builder::oidcIdTokenMetadata
        );
        if (oidcIdToken != null) {
            builder.oidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
        }

        return builder.build();
    }

    private <T extends OAuth2Token> void setTokenValues(
            OAuth2Authorization.Token<T> token,
            Consumer<String> tokenValueConsumer,
            Consumer<Instant> issuedAtConsumer,
            Consumer<Instant> expiresAtConsumer,
            Consumer<String> metadataConsumer) {
        if (token != null) {
            T oAuth2Token = token.getToken();
            tokenValueConsumer.accept(oAuth2Token.getTokenValue());
            issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
            expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
            metadataConsumer.accept(writeMap(token.getMetadata()));
        }
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return StringUtils.hasText(data) ?
                    objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {}) :
                    Map.of();
        } catch (Exception ex) {
            throw new IllegalArgumentException(JSON_PARSE_FAILED + ": " + ex.getMessage(), ex);
        }
    }

    private String writeMap(Map<String, Object> metadata) {
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (Exception ex) {
            throw new IllegalArgumentException(JSON_WRITE_FAILED + ": " + ex.getMessage(), ex);
        }
    }
}
