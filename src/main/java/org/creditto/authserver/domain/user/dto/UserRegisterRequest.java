package org.creditto.authserver.domain.user.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public record UserRegisterRequest(
        @NotBlank(message = "이름은 필수입니다")
        String name,

        @NotNull(message = "생년월일은 필수입니다")
        LocalDate birthDate,

        @NotBlank(message = "국가코드는 필수입니다")
        @Size(min = 2, max = 3, message = "국가코드는 2자리 또는 3자리여야 합니다")
        String countryCode,

        @NotBlank(message = "전화번호는 필수입니다")
        @Pattern(regexp = "^010-\\d{4}-\\d{4}$", message = "전화번호 형식이 올바르지 않습니다 (예: 010-1234-5678)")
        String phoneNo,

        @NotBlank(message = "주소는 필수입니다")
        String address
) {
}