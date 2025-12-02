package org.creditto.authserver.client.service;

import org.creditto.authserver.client.entity.OAuth2AuthorizationEntity;
import org.creditto.authserver.client.repository.OAuth2AuthorizationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JpaOAuth2AuthorizationServiceTest {

    @Mock
    private OAuth2AuthorizationRepository authorizationRepository;
    @Mock
    private RegisteredClientRepository registeredClientRepository;

    private JpaOAuth2AuthorizationService service;
    private RegisteredClient registeredClient;
    private OAuth2Authorization authorization;

    @BeforeEach
    void setUp() {
        service = new JpaOAuth2AuthorizationService(authorizationRepository, registeredClientRepository);
        registeredClient = RegisteredClient.withId("registered-client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .clientName("테스트 클라이언트")
                .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().reuseRefreshTokens(true).build())
                .build();

        Instant issuedAt = Instant.parse("2024-01-01T10:00:00Z");
        OAuth2AccessToken token = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "access-token",
                issuedAt,
                issuedAt.plusSeconds(120),
                Set.of("read")
        );

        authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .id("authorization-id")
                .principalName("principal-user")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(Set.of("read"))
                .attribute(OAuth2ParameterNames.STATE, "state-value")
                .token(token, metadata -> metadata.put("meta", "value"))
                .build();
    }

    @Test
    @DisplayName("Authorization 저장 시 JPA 엔티티로 변환되어 저장된다")
    void save_persistsConvertedEntity() {
        // given
        when(authorizationRepository.findById(authorization.getId())).thenReturn(Optional.empty());

        // when
        service.save(authorization);

        // then
        ArgumentCaptor<OAuth2AuthorizationEntity> captor = ArgumentCaptor.forClass(OAuth2AuthorizationEntity.class);
        verify(authorizationRepository).save(captor.capture());
        OAuth2AuthorizationEntity entity = captor.getValue();
        assertThat(entity.getPrincipalName()).isEqualTo("principal-user");
        assertThat(entity.getAccessTokenValue()).isEqualTo("access-token");
        assertThat(entity.getAuthorizedScopes()).contains("read");
    }

    @Test
    @DisplayName("액세스 토큰으로 Authorization을 조회하면 도메인 객체로 복원된다")
    void findByToken_returnsAuthorization() {
        // given
        AtomicReference<OAuth2AuthorizationEntity> storedEntity = new AtomicReference<>();
        when(authorizationRepository.findById("authorization-id")).thenReturn(Optional.empty());
        when(authorizationRepository.save(any(OAuth2AuthorizationEntity.class))).thenAnswer(invocation -> {
            OAuth2AuthorizationEntity entity = invocation.getArgument(0);
            storedEntity.set(entity);
            return entity;
        });

        service.save(authorization);

        when(authorizationRepository.findByAccessTokenValue("access-token"))
                .thenReturn(Optional.ofNullable(storedEntity.get()));
        when(registeredClientRepository.findById("registered-client-id")).thenReturn(registeredClient);

        // when
        OAuth2Authorization result = service.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getPrincipalName()).isEqualTo("principal-user");
        OAuth2Authorization.Token<OAuth2AccessToken> token = result.getToken(OAuth2AccessToken.class);
        assertThat(token).isNotNull();
        assertThat(token.getToken().getTokenValue()).isEqualTo("access-token");
    }

}
