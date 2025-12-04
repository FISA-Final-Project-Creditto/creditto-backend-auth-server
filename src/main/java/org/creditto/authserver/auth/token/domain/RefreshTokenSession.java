package org.creditto.authserver.auth.token.domain;

import lombok.Builder;

import java.time.Instant;

@Builder(toBuilder = true)
public record RefreshTokenSession(
        String userId,
        String username,
        String roles,
        String certificateId,
        String certificateSerial,
        String countryCode,
        String phoneNo,
        String clientId,
        String tokenValue,
        Instant issuedAt,
        Instant expiresAt,
        String sessionId,
        String ipAddress,
        String userAgent
) {
    public RefreshTokenSession rotate(String newTokenValue, Instant newIssuedAt, Instant newExpiresAt, String newIp, String newUserAgent) {
        return this.toBuilder()
                .tokenValue(newTokenValue)
                .issuedAt(newIssuedAt)
                .expiresAt(newExpiresAt)
                .ipAddress(newIp)
                .userAgent(newUserAgent)
                .sessionId(newTokenValue)
                .build();
    }
}
