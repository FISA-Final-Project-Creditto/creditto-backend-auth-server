package org.creditto.authserver.auth;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.constants.CustomGrantType;
import org.creditto.authserver.client.entity.OAuth2RegisteredClient;
import org.creditto.authserver.client.entity.RegisteredClientMapper;
import org.creditto.authserver.client.repository.OAuth2RegisteredClientRepository;
import org.springframework.beans.factory.annotation.Value;
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

    @Value("${CORE_BANKING_ID}")
    private String coreBankingId;

    @Value("${CORE_BANKING_SECRET}")
    private String coreBankingSecret;

    @Value("${CORE_BANKING_NAME}")
    private String coreBankingName;

    @Value("${CORE_BANKING_URL}")
    private String coreBankingUrl;

    @Value("${CREDITTO_ID}")
    private String credittoId;

    @Value("${CREDITTO_SECRET}")
    private String credittoSecret;

    @Value("${CREDITTO_NAME}")
    private String credittoName;

    @Value("${CREDITTO_URL}")
    private String credittoUrl;

    @Bean
    public CommandLineRunner initOAuth2Clients() {
        return args -> {

            // CoreBanking 클라이언트 등록
            if (clientRepository.findByClientId(coreBankingId).isEmpty()) {
                RegisteredClient coreBankingClient = createCoreBankingClient();
                OAuth2RegisteredClient entity = clientMapper.convertToEntity(coreBankingClient);
                clientRepository.save(entity);
                log.info("CoreBanking 클라이언트 등록 완료");
            } else {
                log.info("CoreBanking 클라이언트 이미 존재");
            }

            // Creditto 클라이언트 등록
            if (clientRepository.findByClientId(credittoId).isEmpty()) {
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
                .clientId(coreBankingId)
                .clientSecret(passwordEncoder.encode(coreBankingSecret))
                .clientName(coreBankingName)

                // 클라이언트 인증 방법
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)

                // Grant Types
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(CustomGrantType.CERTIFICATE)

                // 리다이렉트 URI
                .redirectUri(coreBankingUrl + "/login/oauth2/code/corebanking")
                .redirectUri(coreBankingUrl + "/authorized")
                .postLogoutRedirectUri(coreBankingUrl + "/logout")

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
                        .accessTokenTimeToLive(Duration.ofDays(30))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
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
                .clientId(credittoId)
                .clientSecret(passwordEncoder.encode(credittoSecret))
                .clientName(credittoName)

                // 클라이언트 인증 방법
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)

                // Grant Types
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(CustomGrantType.CERTIFICATE)

                // 리다이렉트 URI
                .redirectUri(credittoUrl + "/login/oauth2/code/creditto")
                .redirectUri(credittoUrl + "/authorized")
                .postLogoutRedirectUri(credittoUrl + "/logout")

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
                        .accessTokenTimeToLive(Duration.ofDays(30))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
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