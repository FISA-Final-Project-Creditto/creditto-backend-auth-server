package org.creditto.authserver.auth.authentication;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.certificate.service.CertificateService;
import org.creditto.authserver.user.entity.User;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateAuthenticationProvider implements AuthenticationProvider {

    private final CertificateService certificateService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CertificateAuthenticationToken token = (CertificateAuthenticationToken) authentication;

        String serialNum = token.getCertificateSerial();
        String simplePassword = token.getCredentials();
        String clientId = token.getClientId();

        try {
            // 인증서 검증
            Certificate certificate = certificateService.authenticateCertificate(serialNum, simplePassword);

            User user = certificate.getUser();

            List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                    .map(SimpleGrantedAuthority::new)
                    .toList();

            return CertificateAuthenticationToken.createAuthenticatedToken(authorities, serialNum, clientId, user);
        } catch (IllegalArgumentException e) {
            log.error("인증서 인증 실패: {}", e.getMessage());
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, e.getMessage(), null)
            );
        } catch (Exception e) {
            log.error("인증서 인증 중 오류 발생");
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR, "", null)
            );
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CertificateAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
