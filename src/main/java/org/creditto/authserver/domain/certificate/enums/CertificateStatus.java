package org.creditto.authserver.domain.certificate.enums;

import lombok.Getter;

@Getter
public enum CertificateStatus {
    ACTIVE("정상"),
    EXPIRED("만료"),
    DISABLE("정지"),
    REVOKE("제거");

    private final String state;

    CertificateStatus(String state) {
        this.state = state;
    }
}
