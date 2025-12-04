package org.creditto.authserver.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.authentication.RequestClientInfo;
import org.creditto.authserver.auth.constants.ClaimConstants;
import org.creditto.authserver.auth.context.ManualAuthorizationServerContext;
import org.creditto.authserver.auth.dto.LogoutRequest;
import org.creditto.authserver.auth.dto.RefreshTokenRequest;
import org.creditto.authserver.auth.dto.TokenResponse;
import org.creditto.authserver.auth.jwt.CertificateOAuth2TokenGenerator;
import org.creditto.authserver.auth.token.domain.RefreshTokenSession;
import org.creditto.authserver.auth.token.service.RefreshTokenService;
import org.creditto.authserver.global.response.error.ErrorMessage;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Set;

import static org.creditto.authserver.auth.constants.Constants.USER_AGENT;
import static org.creditto.authserver.global.response.error.ErrorMessage.INVALID_CLIENT;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final RegisteredClientRepository registeredClientRepository;
    private final RefreshTokenService refreshTokenService;
    private final CertificateOAuth2TokenGenerator tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;
    private final AuthorizationServerSettings authorizationServerSettings;

    public TokenResponse refreshToken(RefreshTokenRequest request, HttpServletRequest httpServletRequest) {
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(request.clientId());
        clientNullCheck(registeredClient, request.clientId());

        RequestClientInfo clientInfo = RequestClientInfo.from(
                httpServletRequest.getRemoteAddr(),
                httpServletRequest.getHeader(USER_AGENT)
        );

        RefreshTokenSession session = refreshTokenService.validate(request.refreshToken(), request.clientId());
        OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
                registeredClient,
                registeredClient.getClientAuthenticationMethods().stream().findFirst().orElseThrow(),
                registeredClient.getClientSecret()
        );

        OAuth2Authorization.Builder authorizationBuilder = buildAuthorizationFromSession(registeredClient, session);
        OAuth2RefreshTokenAuthenticationToken authenticationToken =
                new OAuth2RefreshTokenAuthenticationToken(request.refreshToken(), clientPrincipal, Set.of(), Map.of());

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizedScopes(registeredClient.getScopes())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrant(authenticationToken);

        tokenContextBuilder.authorizationServerContext(new ManualAuthorizationServerContext(authorizationServerSettings));

        OAuth2Authorization authorizationBeforeTokens = authorizationBuilder.build();
        tokenContextBuilder.authorization(authorizationBeforeTokens);

        OAuth2AccessToken accessToken = generateAccessToken(tokenContextBuilder);
        authorizationBuilder.accessToken(accessToken);

        OAuth2RefreshToken newRefreshToken = generateRefreshToken(registeredClient, tokenContextBuilder);
        if (newRefreshToken != null) {
            authorizationBuilder.refreshToken(newRefreshToken);
            refreshTokenService.rotate(session, newRefreshToken, clientInfo);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        authorizationService.save(authorization);

        log.info("Refresh Token 재발급 완료 - userId: {}, clientId: {}", session.userId(), session.clientId());

        return new TokenResponse(
                OAuth2AccessToken.TokenType.BEARER.getValue(),
                accessToken.getTokenValue(),
                accessToken.getExpiresAt(),
                newRefreshToken != null ? newRefreshToken.getTokenValue() : request.refreshToken(),
                newRefreshToken != null ? newRefreshToken.getExpiresAt() : session.expiresAt()
        );
    }

    public void logout(LogoutRequest request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    private OAuth2Authorization.Builder buildAuthorizationFromSession(RegisteredClient registeredClient, RefreshTokenSession session) {
        Set<String> scopes = registeredClient.getScopes();
        return OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(session.userId())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizedScopes(scopes)
                .attribute(ClaimConstants.CERT_SERIAL_CAMEL, session.certificateSerial())
                .attribute(ClaimConstants.CERT_ID, session.certificateId())
                .attribute(ClaimConstants.USER_ID, session.userId())
                .attribute(ClaimConstants.USERNAME, session.username())
                .attribute(ClaimConstants.COUNTRY_CODE, session.countryCode())
                .attribute(ClaimConstants.USER_PHONE_NO, session.phoneNo())
                .attribute(ClaimConstants.ROLES, session.roles());
    }

    private OAuth2AccessToken generateAccessToken(DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
        OAuth2TokenContext tokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .build();
        OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            throw new IllegalStateException(ErrorMessage.TOKEN_GENERATION_FAILED);
        }
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(),
                tokenContext.getAuthorizedScopes()
        );
    }

    private OAuth2RefreshToken generateRefreshToken(RegisteredClient registeredClient, DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            return null;
        }
        OAuth2TokenContext tokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();
        OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
        if (generatedRefreshToken == null) {
            return null;
        }
        return (OAuth2RefreshToken) generatedRefreshToken;
    }

    private void clientNullCheck(RegisteredClient registeredClient, String clientId) {
        if (registeredClient == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("invalid_client", INVALID_CLIENT + ": " + clientId, null)
            );
        }
    }
}
