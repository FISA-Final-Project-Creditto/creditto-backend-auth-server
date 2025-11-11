package org.creditto.authserver.auth.authentication;

import lombok.*;

/**
 * 인증 시 요청 메타데이터를 담는 DTO
 */
@Builder(access = AccessLevel.PRIVATE)
public record RequestClientInfo(String ipAddress, String userAgent) {
    public static RequestClientInfo from(String ipAddress, String userAgent) {
        return RequestClientInfo.builder()
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();
    }
}

