package org.creditto.authserver.auth.authentication;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.constants.ClaimConstants;
import org.creditto.authserver.auth.jwt.CertificateOAuth2TokenGenerator;
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

import java.util.*;

import static org.creditto.authserver.auth.constants.Constants.CERTIFICATE;
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
    private final CertificateOAuth2TokenGenerator tokenGenerator;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CertificateAuthenticationToken certificateToken = (CertificateAuthenticationToken) authentication;

        // 1. 클라이언트 검증
        String clientId = certificateToken.getClientId();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        clientNullCheck(registeredClient, clientId);

        // 2. 인증서 기반 인증 수행
        String certificateSerial = certificateToken.getCertificateSerial();
        String simplePassword = certificateToken.getCredentials();
        Certificate certificate = authenticateWithCertificate(certificateToken, certificateSerial, simplePassword);
        User user = certificate.getUser();

        // 3. Principal 생성 (OAuth2ClientAuthenticationToken 생성) / 인증된 주체 정보
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
                registeredClient,
                ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                registeredClient.getClientSecret()
        );

        // 4. OAuth2Authorization Builder 생성 및 민감한 정보 저장
        // Jackson 직렬화/역직렬화 안전을 위해 Long은 String으로, Roles는 String 리스트로 저장
        OAuth2Authorization.Builder authorizationBuilder = buildOAuth2AuthorizationSecret(registeredClient, user, certificateSerial, certificate);

        // 5. DefaultOAuth2TokenContext 기본 정보 저장
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = buildOAuth2TokenContextBasic(registeredClient, clientPrincipal, certificateToken);

        // 6. Access Token 생성
        OAuth2TokenContext tokenContext = tokenContextBuilder.build();
        OAuth2AccessToken accessToken = generateOAuth2AccessToken(tokenContext);
        authorizationBuilder.accessToken(accessToken);

        // 7. Refresh Token 생성
        OAuth2RefreshToken refreshToken = generateOAuth2RefreshToken(registeredClient, tokenContextBuilder);

        if (refreshToken != null) {
            authorizationBuilder.refreshToken(refreshToken);
        }

        // 8. OAuth2Authorization 저장
        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        log.info("인증서 기반 OAuth2 토큰 발급 완료 - 사용자: {}, 인증서: {}", user.getName(), certificateSerial);

        // 8. OAuth2AccessTokenAuthenticationToken 반환
        Map<String, Object> additionalParameters = oAuth2AuthenticationTokenParameter(user);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                clientPrincipal,
                accessToken,
                refreshToken,
                additionalParameters
        );
    }

    /**
     * authentication에서 추출한 client 검사 및 예외 처리
     * @param registeredClient 검사할 Client 객체
     * @param clientId Error 반환시 필요한 ClientId
     */
    private static void clientNullCheck(RegisteredClient registeredClient, String clientId) {
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, INVALID_CLIENT + ": " + clientId, null)
            );
        }
    }

    /**
     * 인증서 기반 인증
     * @param certificateToken 인증 객체 (Authorization)
     * @param certificateSerial 인증서 SerialNumber
     * @param simplePassword 인증서 간편 비밀번호
     * @return Certificate
     */
    private Certificate authenticateWithCertificate(CertificateAuthenticationToken certificateToken, String certificateSerial, String simplePassword) {
        String ipAddress = null;
        String userAgent = null;
        Object details = certificateToken.getDetails();
        if (details instanceof RequestClientInfo info) {
            ipAddress = info.ipAddress();
            userAgent = info.userAgent();
        }

        return certificateService.authenticateWithCertificate(certificateSerial, simplePassword, ipAddress, userAgent);
    }

    /**
     * OAuth2Authorization에 민감정보 저장
     * @param registeredClient 인증된 Client
     * @param user 인증받는 대상인 user
     * @param certificateSerial user 소유의 인증서 Serial Number
     * @param certificate user 소유의 인증서
     * @return OAuth2Authorization.Builder
     */
    private static OAuth2Authorization.Builder buildOAuth2AuthorizationSecret(RegisteredClient registeredClient, User user, String certificateSerial, Certificate certificate) {
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(user.getExternalUserId())
                .authorizationGrantType(new AuthorizationGrantType(CERTIFICATE)) // Grant Type 설정
                .attribute(ClaimConstants.CERT_SERIAL_CAMEL, certificateSerial) // 인증서 Serial Number
                .attribute(ClaimConstants.CERT_ID, certificate.getId().toString()) // 인증서 Id
                .attribute(ClaimConstants.EXTERNAL_USER_ID, user.getExternalUserId()) // User의 외부노출 Id
                .attribute(ClaimConstants.USERNAME, user.getName()) // User 이름
                .attribute(ClaimConstants.COUNTRY_CODE, user.getCountryCode()) // User 국가코드
                .attribute(ClaimConstants.USER_PHONE_NO, user.getPhoneNo()) // User 전화번호
                .attribute(ClaimConstants.ROLES, user.mapRoleListToString());
    }

    /**
     * OAuth2TokenContext에 담을 기본 정보 저장
     * @param registeredClient 인증된 Client
     * @param clientPrincipal 인증된 Client Principal
     * @param certificateToken 인증 객체 (Authorization)
     * @return DefaultOAuth2TokenContext.Builder
     */
    private static DefaultOAuth2TokenContext.Builder buildOAuth2TokenContextBasic(
            RegisteredClient registeredClient,
            OAuth2ClientAuthenticationToken clientPrincipal,
            CertificateAuthenticationToken certificateToken
    ) {
        return DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(registeredClient.getScopes())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType(CERTIFICATE))
                .authorizationGrant(certificateToken);
    }

    /**
     * OAuth2AccessToken 생성
     * @param tokenContext OAuth2AccessToken에 들어갈 정보가 담긴 Context
     * @return OAuth2AccessToken
     */
    private OAuth2AccessToken generateOAuth2AccessToken(OAuth2TokenContext tokenContext) {
        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        validGeneratedAccessToken(generatedAccessToken);
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                tokenContext.getAuthorizedScopes()
        );
    }

    /**
     *
     * @param registeredClient 인증된 Client
     * @param tokenContextBuilder tokenContext 정보가 담긴 tokenContextBuilder
     * @return @Nullable OAuth2RefreshToken
     */
    private OAuth2RefreshToken generateOAuth2RefreshToken(RegisteredClient registeredClient, DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
        OAuth2TokenContext tokenContext;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {

            tokenContext = tokenContextBuilder
                    .tokenType(OAuth2TokenType.REFRESH_TOKEN) // 토큰 타입 변경 (기존 ACCESS_TOKEN -> REFRESH_TOKEN))
                    .build();

            OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext); // 변경된 타입에 의해 RefreshToken 발급
            if (generatedRefreshToken != null) {
                return (OAuth2RefreshToken) generatedRefreshToken;
            }
        }
        return null;
    }

    private static Map<String, Object> oAuth2AuthenticationTokenParameter(User user) {
        Map<String, Object> additionalParameters = new HashMap<>();
        additionalParameters.put(ClaimConstants.EXTERNAL_USER_ID, user.getExternalUserId());
        additionalParameters.put(ClaimConstants.USERNAME, user.getName());
        additionalParameters.put(ClaimConstants.COUNTRY_CODE, user.getCountryCode());
        return additionalParameters;
    }

    private static void validGeneratedAccessToken(OAuth2Token generatedAccessToken) {
        if (generatedAccessToken == null) {
            throw new IllegalStateException(TOKEN_GENERATION_FAILED);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CertificateAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
