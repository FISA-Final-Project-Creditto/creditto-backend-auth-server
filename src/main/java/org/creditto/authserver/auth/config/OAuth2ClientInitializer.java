package org.creditto.authserver.auth.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.constants.CustomGrantType;
import org.creditto.authserver.client.entity.OAuth2RegisteredClient;
import org.creditto.authserver.client.entity.RegisteredClientMapper;
import org.creditto.authserver.client.repository.OAuth2RegisteredClientRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.UUID;

/**
 * OAuth2 클라이언트 초기 데이터 등록
 *
 * 애플리케이션 시작 시 CoreBanking과 Creditto 클라이언트를 자동 등록
 * 이미 존재하는 경우 스킵
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class OAuth2ClientInitializer {

    private final OAuth2RegisteredClientRepository clientRepository;
    private final RegisteredClientMapper clientMapper;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initOAuth2Clients() {
        return args -> {

            // CoreBanking 클라이언트 등록
            if (clientRepository.findByClientId("corebanking-client").isEmpty()) {
                RegisteredClient coreBankingClient = createCoreBankingClient();
                OAuth2RegisteredClient entity = clientMapper.convertToEntity(coreBankingClient);
                clientRepository.save(entity);
                log.info("CoreBanking 클라이언트 등록 완료");
            } else {
                log.info("CoreBanking 클라이언트 이미 존재");
            }

            // Creditto 클라이언트 등록
            if (clientRepository.findByClientId("creditto-client").isEmpty()) {
                RegisteredClient credittoClient = createCredittoClient();
                OAuth2RegisteredClient entity = clientMapper.convertToEntity(credittoClient);
                clientRepository.save(entity);
                log.info("Creditto 클라이언트 등록 완료");
            } else {
                log.info("Creditto 클라이언트 이미 존재");
            }
        };
    }

    /**
     * CoreBanking 클라이언트 생성
     */
    private RegisteredClient createCoreBankingClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("corebanking-client")
                .clientSecret(passwordEncoder.encode("corebanking-secret"))
                .clientName("Core Banking System")

                // 클라이언트 인증 방법
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)

                // Grant Types
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(CustomGrantType.CERTIFICATE)  // 커스텀

                // 리다이렉트 URI
                .redirectUri("http://localhost:8080/login/oauth2/code/corebanking")
                .redirectUri("http://localhost:8080/authorized")
                .postLogoutRedirectUri("http://localhost:8080/logout")

                // 스코프
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .scope("write")
                .scope("banking.read")
                .scope("banking.write")
                .scope("banking.transfer")

                // 토큰 설정
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())

                // 클라이언트 설정
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())

                .build();
    }

    /**
     * Creditto 클라이언트 생성
     */
    private RegisteredClient createCredittoClient() {
        return RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("creditto-client")
                .clientSecret(passwordEncoder.encode("creditto-secret"))
                .clientName("Credit Service")

                // 클라이언트 인증 방법
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)

                // Grant Types
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(CustomGrantType.CERTIFICATE)

                // 리다이렉트 URI
                .redirectUri("http://localhost:8081/login/oauth2/code/creditto")
                .redirectUri("http://localhost:8081/authorized")
                .postLogoutRedirectUri("http://localhost:8081/logout")

                // 스코프
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .scope("write")
                .scope("credit.read")
                .scope("credit.write")
                .scope("credit.score")

                // 토큰 설정
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())

                // 클라이언트 설정
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())

                .build();
    }
}