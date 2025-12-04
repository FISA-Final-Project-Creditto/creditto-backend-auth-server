package org.creditto.authserver.client.repository;

import org.creditto.authserver.domain.client.entity.OAuth2RegisteredClient;
import org.creditto.authserver.domain.client.entity.RegisteredClientMapper;
import org.creditto.authserver.domain.client.repository.JpaRegisteredClientRepositoryService;
import org.creditto.authserver.domain.client.repository.OAuth2RegisteredClientRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JpaRegisteredClientRepositoryServiceTest {

    @Mock
    private OAuth2RegisteredClientRepository registeredClientRepository;
    @Mock
    private RegisteredClientMapper mapper;

    @InjectMocks
    private JpaRegisteredClientRepositoryService service;

    private RegisteredClient registeredClient;

    @BeforeEach
    void setUp() {
        Instant fixedInstant = Instant.parse("2024-01-01T10:00:00Z");
        registeredClient = RegisteredClient.withId("registered-client-id")
                .clientId("client-id")
                .clientSecret("secret")
                .clientIdIssuedAt(fixedInstant)
                .clientSecretExpiresAt(fixedInstant.plusSeconds(3600))
                .clientName("테스트 클라이언트")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(TokenSettings.builder().reuseRefreshTokens(true).build())
                .build();
    }

    @Test
    @DisplayName("RegisteredClient 저장 시 엔티티로 변환하여 저장소에 위임한다")
    void save_delegatesToJpaRepository() {
        // given
        OAuth2RegisteredClient entity = mock(OAuth2RegisteredClient.class);
        when(mapper.convertToEntity(registeredClient)).thenReturn(entity);

        // when
        service.save(registeredClient);

        // then
        verify(registeredClientRepository).save(entity);
    }

    @Test
    @DisplayName("ID 기준 조회는 Optional 값을 DTO로 변환해 반환한다")
    void findById_returnsRegisteredClient() {
        // given
        OAuth2RegisteredClient entity = mock(OAuth2RegisteredClient.class);

        when(registeredClientRepository.findById("registered-client-id")).thenReturn(Optional.of(entity));
        when(mapper.convertToRegisteredClient(entity)).thenReturn(registeredClient);

        // when
        RegisteredClient result = service.findById("registered-client-id");

        // then
        assertThat(result).isEqualTo(registeredClient);
    }

    @Test
    @DisplayName("ClientId 기준 조회도 존재하지 않으면 null을 반환한다")
    void findByClientId_returnsNullWhenMissing() {
        // given
        when(registeredClientRepository.findByClientId("missing")).thenReturn(Optional.empty());

        // when
        RegisteredClient result = service.findByClientId("missing");

        // then
        assertThat(result).isNull();
    }

}
