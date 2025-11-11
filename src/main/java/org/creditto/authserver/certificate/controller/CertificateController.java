package org.creditto.authserver.certificate.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.certificate.dto.CertificateIssueRequest;
import org.creditto.authserver.certificate.dto.CertificateIssueResponse;
import org.creditto.authserver.certificate.service.CertificateService;
import org.creditto.authserver.global.response.ApiResponseUtil;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.response.SuccessCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@Slf4j
@RestController
@RequestMapping("/api/certificate")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    /**
     * 인증서 발급
     */
    @PostMapping("/issue")
    public ResponseEntity<BaseResponse<CertificateIssueResponse>> issueCertificate(@Valid @RequestBody CertificateIssueRequest request) {
        log.info("인증서 발급 요청 - 전화번호: {}", request.phoneNo());
        return ApiResponseUtil.success(SuccessCode.OK, certificateService.issueCertificate(request));
    }
}