package org.creditto.authserver.certificate.dto;

import java.time.LocalDate;

public record CertificateIssueRequest(
        String name,
        String phoneNo,
        LocalDate birthDate,
        String simplePassword
) { }