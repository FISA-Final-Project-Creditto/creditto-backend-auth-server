package org.creditto.authserver.auth.authentication;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.constants.ClaimConstants;
import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.certificate.service.CertificateService;
import org.creditto.authserver.user.entity.User;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.util.*;

import static org.creditto.authserver.auth.constants.Constants.CERTIFICATE;
import static org.creditto.authserver.auth.constants.Constants.REFRESH_TOKEN;
import static org.creditto.authserver.global.response.error.ErrorMessage.INVALID_CLIENT;
import static org.creditto.authserver.global.response.error.ErrorMessage.TOKEN_GENERATION_FAILED;

/**
 * 인증서 기반 Grant Type을 처리하는 AuthenticationProvider
 * CertificateAuthenticationToken을 받아 인증 후 OAuth2AccessTokenAuthenticationToken을 반환
 */
@Slf4j
@RequiredArgsConstructor
public class CertificateGrantAuthenticationProvider implements AuthenticationProvider {

    private final CertificateService certificateService;
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CertificateAuthenticationToken certificateToken = (CertificateAuthenticationToken) authentication;

        // 1. 클라이언트 검증
        String clientId = certificateToken.getClientId();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new IllegalArgumentException(INVALID_CLIENT + ": " + clientId);
        }

        // 2. 인증서 기반 인증 수행
        String certificateSerial = certificateToken.getCertificateSerial();
        String simplePassword = certificateToken.getCredentials();

        Certificate certificate = certificateService.authenticateWithCertificate(certificateSerial, simplePassword);
        User user = certificate.getUser();

        // 3. Principal 생성 (OAuth2ClientAuthenticationToken 생성)
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
                registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                registeredClient.getClientSecret()
        );

        // 5. OAuth2Authorization Builder 생성 및 민감한 정보 저장
        // Jackson 직렬화/역직렬화를 위해 Long은 String으로, Set은 List로 변환하여 저장
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getExternalUserId())
                .authorizationGrantType(new AuthorizationGrantType(CERTIFICATE))
                .attribute(ClaimConstants.CERT_SERIAL_CAMEL, certificateSerial)
                .attribute(ClaimConstants.CERT_ID, certificate.getId().toString())
                .attribute(ClaimConstants.EXTERNAL_USER_ID, user.getExternalUserId())
                .attribute(ClaimConstants.USERNAME, user.getName())
                .attribute(ClaimConstants.USER_PHONE_NO, user.getPhoneNo())
                .attribute(ClaimConstants.ROLES, new ArrayList<>(user.getRoles()));

        // 6. Access Token 생성
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(registeredClient.getScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType(CERTIFICATE))
                .authorizationGrant(certificateToken);

        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new IllegalStateException(TOKEN_GENERATION_FAILED);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                tokenContext.getAuthorizedScopes()
        );

        authorizationBuilder.accessToken(accessToken);

        // 7. Refresh Token 생성
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(new AuthorizationGrantType(REFRESH_TOKEN))) {

            tokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                    .build();

            OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null) {
                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                authorizationBuilder.refreshToken(refreshToken);
            }
        }

        // 8. OAuth2Authorization 저장
        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        log.info("인증서 기반 OAuth2 토큰 발급 완료 - 사용자: {}, 인증서: {}", user.getName(), certificateSerial);

        // 9. OAuth2AccessTokenAuthenticationToken 반환
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(ClaimConstants.EXTERNAL_USER_ID, user.getExternalUserId());
        additionalParameters.put(ClaimConstants.USERNAME, user.getName());

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                additionalParameters
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CertificateAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
