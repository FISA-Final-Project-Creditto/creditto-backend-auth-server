package org.creditto.authserver.auth.authentication;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * 서비스에서 이용할 인증 객체
 * CertificateAuthenticationToken < AbstractAuthenticationToken < Authentication
 * AbstractAuthenticationToken은 Authentication을 구현한 추상 클래스
 */
@Getter
public class CertificateAuthenticationToken extends AbstractAuthenticationToken {

    // 인증서 시리얼 넘버
    private final String certificateSerial;

    // 간편 비밀번호
    private final String simplePassword;

    // 클라이언트 ID
    private final String clientId;

    private transient Object principal;

    // 인증 전
    private CertificateAuthenticationToken(String certificateSerial, String simplePassword, String clientId) {
        super(null);
        this.certificateSerial = certificateSerial;
        this.simplePassword = simplePassword;
        this.clientId = clientId;
        super.setAuthenticated(false); // 미인증
    }

    // 익명 인증 객체 (익명 토큰)
    public static CertificateAuthenticationToken createAnonymousToken(String certificateSerial, String simplePassword, String clientId) {
        return new CertificateAuthenticationToken(certificateSerial, simplePassword, clientId);
    }


    @Override
    public String getCredentials() {
        return simplePassword;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
