package org.creditto.authserver.certificate.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.time.LocalDate;

public record CertificateIssueRequest(

        @NotBlank(message = "유저 ID는 필수입니다")
        String externalUserId,

        @NotBlank(message = "이름은 필수입니다")
        String name,

        @NotBlank(message = "전화번호는 필수입니다")
        @Pattern(regexp = "^010-\\d{4}-\\d{4}$", message = "전화번호 형식이 올바르지 않습니다 (예: 010-1234-5678)")
        String phoneNo,

        @NotNull(message = "생년월일은 필수입니다")
        LocalDate birthDate,

        @NotBlank(message = "간편비밀번호는 필수입니다")
        @Pattern(regexp = "\\d{6}", message = "간편비밀번호는 6자리 숫자여야 합니다.")
        String simplePassword
) { }