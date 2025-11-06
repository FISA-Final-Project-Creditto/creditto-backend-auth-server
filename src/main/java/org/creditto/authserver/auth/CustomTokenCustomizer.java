package org.creditto.authserver.auth;

import org.creditto.authserver.auth.authentication.CertificateAuthenticationToken;
import org.creditto.authserver.auth.constants.ClaimConstants;
import org.creditto.authserver.auth.constants.Constants;
import org.creditto.authserver.user.entity.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;

import static org.creditto.authserver.auth.constants.Constants.ACCESS_TOKEN;

@Component
public class CustomTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        Authentication authentication = context.getPrincipal();

        OAuth2TokenType tokenType = context.getTokenType();

        // Access Token에만 Claim 추가
        if (tokenType.getValue().equals(ACCESS_TOKEN)) {
            if (authentication instanceof CertificateAuthenticationToken certToken) {
                User user = (User) certToken.getPrincipal();
                List<String> authorities = user.getRoles().stream().toList();

                context.getClaims()
                        .claim(ClaimConstants.USER_ID, user.getId())
                        .claim(ClaimConstants.NAME, user.getName())
                        .claim(ClaimConstants.CERT_SERIAL, certToken.getCertificateSerial())
                        .claim(ClaimConstants.AUTHORITIES, authorities)
                        .claim(ClaimConstants.AUTH_METHOD, Constants.CERTIFICATE);
            }
        } else {
            context.getClaims()
                    .claim(ClaimConstants.AUTH_METHOD, Constants.STANDARD)
                    .claim(
                            ClaimConstants.AUTHORITIES,
                            authentication.getAuthorities().stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .toList()
                    );
        }
    }
}
