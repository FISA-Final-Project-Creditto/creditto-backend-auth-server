package org.creditto.authserver.certificate.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.certificate.dto.CertificateIssueRequest;
import org.creditto.authserver.certificate.dto.CertificateIssueResponse;
import org.creditto.authserver.certificate.dto.CertificateSerialRequest;
import org.creditto.authserver.certificate.service.CertificateService;
import org.creditto.authserver.global.response.ApiResponseUtil;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.response.SuccessCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

import java.util.Map;

import static org.creditto.authserver.auth.constants.Constants.USER_AGENT;

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
    public ResponseEntity<BaseResponse<CertificateIssueResponse>> issueCertificate(
            @Valid @RequestBody CertificateIssueRequest certificateIssueRequest,
            HttpServletRequest request
    ) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader(USER_AGENT);
        return ApiResponseUtil.success(SuccessCode.OK, certificateService.issueCertificate(certificateIssueRequest, ipAddress, userAgent));
    }

    @PostMapping("/serialNumber")
    public ResponseEntity<BaseResponse<Map<String, String>>> getCertificateSerialNum(
            @Valid @RequestBody CertificateSerialRequest certificateSerialRequest
    ) {
        return ApiResponseUtil.success(SuccessCode.OK, certificateService.getSerialNumberByUser(certificateSerialRequest));
    }
}