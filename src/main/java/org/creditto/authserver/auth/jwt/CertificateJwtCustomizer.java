package org.creditto.authserver.auth.jwt;

import lombok.RequiredArgsConstructor;
import org.creditto.authserver.auth.authentication.CertificateAuthenticationToken;
import org.creditto.authserver.auth.constants.ClaimConstants;
import org.creditto.authserver.auth.constants.Constants;
import org.creditto.authserver.certificate.repository.CertificateRepository;
import org.creditto.authserver.user.entity.User;
import org.creditto.authserver.user.enums.UserRoles;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * JWT 토큰 커스터마이저
 * OAuth2Authorization에 저장된 공개 정보를 JWT Claims에 추가
 */
@Component
@RequiredArgsConstructor
public class CertificateJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final CertificateRepository certificateRepository;

    @Override
    public void customize(JwtEncodingContext context) {

        if (!Constants.ACCESS_TOKEN.equals(context.getTokenType().getValue())) {
            return;
        }

        // 1) 재발급 (Authorization 존재)
        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization != null) {

            Object extId = authorization.getAttribute(ClaimConstants.EXTERNAL_USER_ID);
            Object username = authorization.getAttribute(ClaimConstants.USERNAME);
            Object roles = authorization.getAttribute(ClaimConstants.ROLES);
            Object countryCode = authorization.getAttribute(ClaimConstants.COUNTRY_CODE);

            if (extId != null) context.getClaims().claim(ClaimConstants.EXTERNAL_USER_ID, extId);
            if (username != null) context.getClaims().claim(ClaimConstants.USERNAME, username);
            if (roles != null) context.getClaims().claim(ClaimConstants.ROLES, roles);
            if (countryCode != null) context.getClaims().claim(ClaimConstants.COUNTRY_CODE, countryCode);

            return;
        }

        // 2) 최초 발급 (authorization == null)
        Object grant = context.getAuthorizationGrant();
        if (grant instanceof CertificateAuthenticationToken certGrant) {

            String serial = certGrant.getCertificateSerial();

            certificateRepository.findBySerialNumber(serial)
                    .ifPresent(cert -> {

                        User user = cert.getUser();
                        Set<UserRoles> userRoles = user.getRoles();

                        context.getClaims().subject(user.getExternalUserId());
                        context.getClaims().claim(ClaimConstants.EXTERNAL_USER_ID, user.getExternalUserId());
                        context.getClaims().claim(ClaimConstants.USERNAME, user.getName());
                        context.getClaims().claim(ClaimConstants.COUNTRY_CODE, user.getCountryCode());

                        List<String> roleNames = userRoles.stream()
                                .map(Enum::name)
                                .toList();
                        context.getClaims().claim(ClaimConstants.ROLES, roleNames);
                    });
        }
    }
}
