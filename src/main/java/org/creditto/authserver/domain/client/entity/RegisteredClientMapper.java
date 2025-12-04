package org.creditto.authserver.domain.client.entity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.creditto.authserver.auth.constants.SettingsConstants;
import org.creditto.authserver.client.entity.sub.*;
import org.creditto.authserver.domain.client.entity.sub.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import static org.creditto.authserver.auth.constants.Constants.SECONDS;
import static org.creditto.authserver.global.response.error.ErrorMessage.*;

@Component
@RequiredArgsConstructor
public class RegisteredClientMapper {

    private final ObjectMapper objectMapper;

    public RegisteredClient convertToRegisteredClient(OAuth2RegisteredClient client) {

        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName());

        // 인증 방식
        client.getClientAuthenticationMethods().forEach(method ->
                builder.clientAuthenticationMethod(
                        new ClientAuthenticationMethod(method.getAuthenticationMethod())
                )
        );

        // 인가 Grant Type
        client.getAuthorizationGrantTypes().forEach(grantType ->
                builder.authorizationGrantType(
                        new AuthorizationGrantType(grantType.getGrantType())
                )
        );

        // 리다이렉트 URI
        client.getRedirectUris().forEach(uri ->
                builder.redirectUri(uri.getRedirectUri())
        );

        // Post Logout 리다이렉트 URI
        client.getPostLogoutRedirectUris().forEach(uri ->
                builder.postLogoutRedirectUri(uri.getPostLogoutRedirectUri())
        );

        // 스코프
        client.getScopes().forEach(scope ->
                builder.scope(scope.getScope())
        );

        // 클라이언트 설정
        if (client.getClientSettings() != null) {
            builder.clientSettings(parseClientSettings(client.getClientSettings()));
        }

        // 토큰 설정
        if (client.getTokenSettings() != null) {
            builder.tokenSettings(parseTokenSettings(client.getTokenSettings()));
        }

        return builder.build();
    }

    public OAuth2RegisteredClient convertToEntity(RegisteredClient registeredClient) {

        OAuth2RegisteredClient entity = OAuth2RegisteredClient.builder()
                .id(registeredClient.getId())
                .clientId(registeredClient.getClientId())
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
                .clientSecret(registeredClient.getClientSecret())
                .clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt())
                .clientName(registeredClient.getClientName())
                .clientSettings(writeClientSettings(registeredClient.getClientSettings()))
                .tokenSettings(writeTokenSettings(registeredClient.getTokenSettings()))
                .build();

        // 클라이언트 인증 방법
        registeredClient.getClientAuthenticationMethods().forEach(method -> {
            ClientAuthenticationMethodEntity authMethod = ClientAuthenticationMethodEntity.of(method.getValue());
            entity.addClientAuthenticationMethod(authMethod);
        });

        // 인가 Grant Type
        registeredClient.getAuthorizationGrantTypes().forEach(grantType -> {
            AuthorizationGrantTypeEntity authGrantType = AuthorizationGrantTypeEntity.of(grantType.getValue());
            entity.addAuthorizationGrantType(authGrantType);
        });

        // 리다이렉트 URI
        registeredClient.getRedirectUris().forEach(uri -> {
            RedirectUriEntity redirectUri = RedirectUriEntity.of(uri);
            entity.addRedirectUri(redirectUri);
        });

        // Post Logout 리다이렉트 URI
        registeredClient.getPostLogoutRedirectUris().forEach(uri -> {
            PostLogoutRedirectUriEntity postLogoutUri = PostLogoutRedirectUriEntity.of(uri);
            entity.addPostLogoutRedirectUri(postLogoutUri);
        });

        // 스코프
        registeredClient.getScopes().forEach(scope -> {
            ClientScope clientScope = ClientScope.of(scope);
            entity.addScope(clientScope);
        });

        return entity;
    }

    /**
     * ClientSettings JSON → 객체 변환
     */
    private ClientSettings parseClientSettings(String json) {
        try {
            Map<String, Object> settings = objectMapper.readValue(json, Map.class);

            ClientSettings.Builder builder = ClientSettings.builder();

            if (settings.containsKey(SettingsConstants.REQUIRE_AUTHORIZATION_CONSENT)) {
                builder.requireAuthorizationConsent(
                        (Boolean) settings.get(SettingsConstants.REQUIRE_AUTHORIZATION_CONSENT)
                );
            }

            if (settings.containsKey(SettingsConstants.REQUIRE_PROOF_KEY)) {
                builder.requireProofKey(
                        (Boolean) settings.get(SettingsConstants.REQUIRE_PROOF_KEY)
                );
            }

            if (settings.containsKey(SettingsConstants.JWK_SET_URL)) {
                builder.jwkSetUrl((String) settings.get(SettingsConstants.JWK_SET_URL));
            }

            return builder.build();

        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(FAILED_PARSE, e);
        }
    }

    /**
     * ClientSettings 객체 → JSON 변환
     */
    private String writeClientSettings(ClientSettings clientSettings) {
        try {
            return objectMapper.writeValueAsString(clientSettings.getSettings());
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(FAILED_SERIALIZED, e);
        }
    }

    /**
     * TokenSettings JSON → 객체 변환
     */
    private TokenSettings parseTokenSettings(String json) {
        try {
            Map<String, Object> settings = objectMapper.readValue(json, Map.class);

            TokenSettings.Builder builder = TokenSettings.builder();

            extractDuration(settings, SettingsConstants.ACCESS_TOKEN_TTL, SettingsConstants.LEGACY_ACCESS_TOKEN_TTL)
                    .ifPresent(builder::accessTokenTimeToLive);

            extractDuration(settings, SettingsConstants.REFRESH_TOKEN_TTL, SettingsConstants.LEGACY_REFRESH_TOKEN_TTL)
                    .ifPresent(builder::refreshTokenTimeToLive);

            extractBoolean(settings, SettingsConstants.REUSE_REFRESH_TOKENS, SettingsConstants.LEGACY_REUSE_REFRESH_TOKENS)
                    .ifPresent(builder::reuseRefreshTokens);

            return builder.build();

        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(FAILED_PARSE, e);
        }
    }

    /**
     * TokenSettings 객체 → JSON 변환
     */
    private String writeTokenSettings(TokenSettings tokenSettings) {
        try {
            return objectMapper.writeValueAsString(tokenSettings.getSettings());
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(FAILED_SERIALIZED, e);
        }
    }

    private Optional<Duration> extractDuration(Map<String, Object> settings, String... keys) {
        for (String key : keys) {
            if (settings.containsKey(key)) {
                return Optional.of(convertToDuration(settings.get(key)));
            }
        }
        return Optional.empty();
    }

    private Duration convertToDuration(Object value) {
        if (value instanceof Map<?, ?> ttl && ttl.containsKey(SECONDS)) {
            return Duration.ofSeconds(((Number) ttl.get(SECONDS)).longValue());
        }

        if (value instanceof Number number) {
            return Duration.ofSeconds(number.longValue());
        }

        if (value instanceof String text && !text.isBlank()) {
            try {
                return Duration.parse(text);
            } catch (java.time.format.DateTimeParseException e) {
                throw new IllegalArgumentException(INVALID_DURATION + value, e);
            }
        }

        throw new IllegalArgumentException(INVALID_DURATION + value);
    }

    private Optional<Boolean> extractBoolean(Map<String, Object> settings, String... keys) {
        for (String key : keys) {
            if (settings.containsKey(key)) {
                Object value = settings.get(key);
                if (value instanceof Boolean bool) {
                    return Optional.of(bool);
                }
                if (value instanceof String text) {
                    return Optional.of(Boolean.parseBoolean(text));
                }
            }
        }
        return Optional.empty();
    }
}
