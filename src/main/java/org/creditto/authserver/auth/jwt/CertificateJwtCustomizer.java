package org.creditto.authserver.auth.jwt;

import lombok.RequiredArgsConstructor;
import org.creditto.authserver.auth.authentication.CertificateAuthenticationToken;
import org.creditto.authserver.auth.constants.ClaimConstants;
import org.creditto.authserver.auth.constants.Constants;
import org.creditto.authserver.domain.certificate.repository.CertificateRepository;
import org.creditto.authserver.domain.user.entity.User;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

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

        // 재발급 (Authorization 존재)
        OAuth2Authorization authorization = context.getAuthorization();
        if (authorization != null) {
            addUserClaims(authorization, context);
            addRoleClaims(authorization, context);
            return;
        }

        // 최초 발급 (authorization == null)
        Object grant = context.getAuthorizationGrant();
        if (grant instanceof CertificateAuthenticationToken certGrant) {

            String serial = certGrant.getCertificateSerial();

            certificateRepository.findBySerialNumber(serial)
                    .ifPresent(cert -> {

                        User user = cert.getUser();

                        context.getClaims().subject(user.getId().toString());
                        context.getClaims().claim(ClaimConstants.USER_ID, user.getId().toString());
                        context.getClaims().claim(ClaimConstants.USERNAME, user.getName());
                        context.getClaims().claim(ClaimConstants.COUNTRY_CODE, user.getCountryCode());
                        context.getClaims().claim(ClaimConstants.ROLES, user.mapUserRolesToList());
                    });
        }
    }

    private void addUserClaims(OAuth2Authorization authorization, JwtEncodingContext context) {
        Stream.of(
                ClaimConstants.USER_ID,
                ClaimConstants.USERNAME,
                ClaimConstants.COUNTRY_CODE
        ).forEach(claimName -> {
            Object claimValue = authorization.getAttribute(claimName);
            if (claimValue != null) {
                context.getClaims().claim(claimName, claimValue);
            }
        });
    }

    private void addRoleClaims(OAuth2Authorization authorization, JwtEncodingContext context) {
        Object rolesAttr = authorization.getAttribute(ClaimConstants.ROLES);
        if (rolesAttr != null) {
            List<String> roleList;
            if (rolesAttr instanceof String csv) {
                roleList = Arrays.stream(csv.split(","))
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .toList();
            } else if (rolesAttr instanceof Collection<?> c) {
                roleList = c.stream()
                        .map(Object::toString)
                        .toList();
            } else {
                roleList = List.of(rolesAttr.toString());
            }
            context.getClaims().claim(ClaimConstants.ROLES, roleList);
        }
    }
}
