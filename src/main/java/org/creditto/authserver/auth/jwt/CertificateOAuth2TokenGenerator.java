package org.creditto.authserver.auth.jwt;

import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.stereotype.Component;

/**
 * OAuth2 토큰 생성기
 * Access Token과 Refresh Token을 생성
 */

@Component
public class CertificateOAuth2TokenGenerator implements OAuth2TokenGenerator<OAuth2Token> {

    private final DelegatingOAuth2TokenGenerator delegate;

    public CertificateOAuth2TokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer
    ) {
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);

        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        this.delegate = new DelegatingOAuth2TokenGenerator(
                jwtGenerator,
                accessTokenGenerator,
                refreshTokenGenerator
        );
    }

    @Override
    public OAuth2Token generate(OAuth2TokenContext context) {
        return this.delegate.generate(context);
    }
}

