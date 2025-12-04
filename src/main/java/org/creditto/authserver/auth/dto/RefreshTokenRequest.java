package org.creditto.authserver.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(
        @NotBlank(message = "refreshToken은 필수입니다.")
        String refreshToken,
        @NotBlank(message = "clientId는 필수입니다.")
        String clientId
) {
}
