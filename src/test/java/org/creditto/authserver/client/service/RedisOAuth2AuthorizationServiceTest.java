package org.creditto.authserver.client.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.creditto.authserver.domain.client.service.RedisOAuth2AuthorizationService;
import org.creditto.authserver.global.redis.AuthorizationEntityMapper;
import org.creditto.authserver.global.redis.AuthorizationKeyManager;
import org.creditto.authserver.global.redis.AuthorizationRedisRepository;
import org.creditto.authserver.global.redis.AuthorizationTtlPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RedisOAuth2AuthorizationServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private RegisteredClientRepository registeredClientRepository;
    @Mock
    private ValueOperations<String, String> valueOperations;

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().findAndRegisterModules();
    private RedisOAuth2AuthorizationService service;
    private RegisteredClient registeredClient;
    private OAuth2Authorization authorization;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        AuthorizationKeyManager keyManager = new AuthorizationKeyManager();
        AuthorizationRedisRepository repository = new AuthorizationRedisRepository(redisTemplate, keyManager, OBJECT_MAPPER);
        AuthorizationEntityMapper mapper = new AuthorizationEntityMapper(registeredClientRepository);
        AuthorizationTtlPolicy ttlPolicy = new AuthorizationTtlPolicy(Duration.ofHours(1));
        service = new RedisOAuth2AuthorizationService(repository, mapper, keyManager, ttlPolicy);

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
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
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
                .token(accessToken, metadata -> metadata.put("meta", "value"))
                .build();
    }

    @Test
    @DisplayName("Authorization 저장 시 Redis에 JSON으로 기록된다")
    void save_persistsAuthorizationInRedis() {
        AtomicReference<String> storedValue = new AtomicReference<>();
        AtomicReference<String> storedKey = new AtomicReference<>();

        doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            Duration ttl = invocation.getArgument(2);
            if (key.startsWith("oauth2:authorization:")) {
                storedKey.set(key);
                storedValue.set(value);
                assertThat(ttl.toSeconds()).isPositive();
            }
            return null;
        }).when(valueOperations).set(any(String.class), any(String.class), any(Duration.class));

        service.save(authorization);

        assertThat(storedKey.get()).isEqualTo("oauth2:authorization:" + authorization.getId());
        assertThat(storedValue.get()).contains("principal-user");
    }

    @Test
    @DisplayName("액세스 토큰으로 Redis에서 Authorization을 복원한다")
    void findByToken_returnsAuthorization() {
        Map<String, String> inMemoryRedis = new ConcurrentHashMap<>();

        doAnswer(invocation -> {
            String key = invocation.getArgument(0);
            String value = invocation.getArgument(1);
            inMemoryRedis.put(key, value);
            return null;
        }).when(valueOperations).set(any(String.class), any(String.class), any(Duration.class));

        when(valueOperations.get(any(String.class))).thenAnswer(invocation -> inMemoryRedis.get(invocation.getArgument(0)));
        when(registeredClientRepository.findById("registered-client-id")).thenReturn(registeredClient);

        service.save(authorization);

        OAuth2Authorization result = service.findByToken("access-token", OAuth2TokenType.ACCESS_TOKEN);

        assertThat(result).isNotNull();
        assertThat(result.getPrincipalName()).isEqualTo("principal-user");
        assertThat(result.getToken(OAuth2AccessToken.class)).isNotNull();
    }

}
