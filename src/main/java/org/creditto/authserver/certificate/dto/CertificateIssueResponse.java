package org.creditto.authserver.certificate.dto;

import lombok.AccessLevel;
import lombok.Builder;
import org.creditto.authserver.certificate.entity.Certificate;

import java.time.LocalDateTime;

@Builder(access = AccessLevel.PRIVATE)
public record CertificateIssueResponse(
        String serialNumber,
        LocalDateTime issuedAt,
        LocalDateTime expiresAt
) {
    public static CertificateIssueResponse from(Certificate certificate) {
        return CertificateIssueResponse.builder()
                .serialNumber(certificate.getSerialNumber())
                .issuedAt(certificate.getIssuedAt())
                .expiresAt(certificate.getExpiresAt())
                .build();
    }
}