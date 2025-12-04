package org.creditto.authserver.global.redis;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.creditto.authserver.domain.client.entity.OAuth2AuthorizationEntity;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.function.Consumer;

import static org.creditto.authserver.global.response.error.AssertErrorMessage.JSON_PARSE_FAILED;
import static org.creditto.authserver.global.response.error.AssertErrorMessage.JSON_WRITE_FAILED;
import static org.creditto.authserver.global.response.error.AssertErrorMessage.REGISTERED_CLIENT_NOT_FOUND_IN_REPO;

@Component
@RequiredArgsConstructor
public class AuthorizationEntityMapper {

    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper metadataObjectMapper = buildMetadataObjectMapper();

    public OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
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

        mapAuthorizationCode(entity, builder);
        mapAccessToken(entity, builder);
        mapRefreshToken(entity, builder);
        mapOidcToken(entity, builder);

        return builder.build();
    }

    public OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization, OAuth2AuthorizationEntity existingEntity) {
        OAuth2AuthorizationEntity.OAuth2AuthorizationEntityBuilder builder = OAuth2AuthorizationEntity.builder()
                .id(authorization.getId())
                .registeredClientId(authorization.getRegisteredClientId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
                .authorizedScopes(StringUtils.collectionToCommaDelimitedString(authorization.getAuthorizedScopes()))
                .attributes(writeMap(authorization.getAttributes()))
                .state(authorization.getAttribute(OAuth2ParameterNames.STATE));

        if (existingEntity != null && existingEntity.getCreatedAt() != null) {
            builder.createdAt(existingEntity.getCreatedAt());
        } else {
            builder.createdAt(LocalDateTime.now());
        }
        setTokenValueOfAuthorization(authorization, builder);
        setTokenValueOfAccessToken(authorization, builder);
        setTokenValueOfRefreshToken(authorization, builder);
        setTokenValueOfOidcToken(authorization, builder);

        return builder.build();
    }

    private void setTokenValueOfOidcToken(OAuth2Authorization authorization, OAuth2AuthorizationEntity.OAuth2AuthorizationEntityBuilder builder) {
        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
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
    }

    private void setTokenValueOfRefreshToken(OAuth2Authorization authorization, OAuth2AuthorizationEntity.OAuth2AuthorizationEntityBuilder builder) {
        setTokenValues(authorization.getToken(OAuth2RefreshToken.class),
                builder::refreshTokenValue,
                builder::refreshTokenIssuedAt,
                builder::refreshTokenExpiresAt,
                builder::refreshTokenMetadata);
    }

    private void setTokenValueOfAccessToken(OAuth2Authorization authorization, OAuth2AuthorizationEntity.OAuth2AuthorizationEntityBuilder builder) {
        setTokenValues(authorization.getToken(OAuth2AccessToken.class),
                builder::accessTokenValue,
                builder::accessTokenIssuedAt,
                builder::accessTokenExpiresAt,
                builder::accessTokenMetadata);

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        if (accessToken != null && accessToken.getToken().getScopes() != null) {
            builder.accessTokenType(accessToken.getToken().getTokenType().getValue());
            builder.accessTokenScopes(StringUtils.collectionToCommaDelimitedString(accessToken.getToken().getScopes()));
        }
    }

    private void setTokenValueOfAuthorization(OAuth2Authorization authorization, OAuth2AuthorizationEntity.OAuth2AuthorizationEntityBuilder builder) {
        setTokenValues(authorization.getToken(OAuth2AuthorizationCode.class),
                builder::authorizationCodeValue,
                builder::authorizationCodeIssuedAt,
                builder::authorizationCodeExpiresAt,
                builder::authorizationCodeMetadata);
    }

    private void mapAuthorizationCode(OAuth2AuthorizationEntity entity, OAuth2Authorization.Builder builder) {
        if (entity.getAuthorizationCodeValue() == null) {
            return;
        }
        OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                entity.getAuthorizationCodeValue(),
                entity.getAuthorizationCodeIssuedAt(),
                entity.getAuthorizationCodeExpiresAt()
        );
        builder.token(authorizationCode, metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
    }

    private void mapAccessToken(OAuth2AuthorizationEntity entity, OAuth2Authorization.Builder builder) {
        if (entity.getAccessTokenValue() == null) {
            return;
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                entity.getAccessTokenValue(),
                entity.getAccessTokenIssuedAt(),
                entity.getAccessTokenExpiresAt(),
                StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes())
        );
        builder.token(accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
    }

    private void mapRefreshToken(OAuth2AuthorizationEntity entity, OAuth2Authorization.Builder builder) {
        if (entity.getRefreshTokenValue() == null) {
            return;
        }
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                entity.getRefreshTokenValue(),
                entity.getRefreshTokenIssuedAt(),
                entity.getRefreshTokenExpiresAt()
        );
        builder.token(refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
    }

    private void mapOidcToken(OAuth2AuthorizationEntity entity, OAuth2Authorization.Builder builder) {
        if (entity.getOidcIdTokenValue() == null) {
            return;
        }
        OidcIdToken idToken = new OidcIdToken(
                entity.getOidcIdTokenValue(),
                entity.getOidcIdTokenIssuedAt(),
                entity.getOidcIdTokenExpiresAt(),
                parseMap(entity.getOidcIdTokenClaims())
        );
        builder.token(idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
    }

    private <T extends OAuth2Token> void setTokenValues(
            OAuth2Authorization.Token<T> token,
            Consumer<String> tokenValueConsumer,
            Consumer<java.time.Instant> issuedAtConsumer,
            Consumer<java.time.Instant> expiresAtConsumer,
            Consumer<String> metadataConsumer
    ) {
        if (token == null || token.getToken() == null) {
            return;
        }
        T source = token.getToken();
        tokenValueConsumer.accept(source.getTokenValue());
        issuedAtConsumer.accept(source.getIssuedAt());
        expiresAtConsumer.accept(source.getExpiresAt());
        metadataConsumer.accept(writeMap(token.getMetadata()));
    }

    private Map<String, Object> parseMap(String data) {
        try {
            return StringUtils.hasText(data)
                    ? metadataObjectMapper.readValue(data, new TypeReference<Map<String, Object>>() {})
                    : Map.of();
        } catch (Exception ex) {
            throw new IllegalArgumentException(JSON_PARSE_FAILED + ": " + ex.getMessage(), ex);
        }
    }

    private String writeMap(Map<String, Object> metadata) {
        try {
            return metadataObjectMapper.writeValueAsString(metadata);
        } catch (Exception ex) {
            throw new IllegalArgumentException(JSON_WRITE_FAILED + ": " + ex.getMessage(), ex);
        }
    }

    private ObjectMapper buildMetadataObjectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = AuthorizationEntityMapper.class.getClassLoader();
        objectMapper.registerModules(SecurityJackson2Modules.getModules(classLoader));
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        return objectMapper;
    }
}
