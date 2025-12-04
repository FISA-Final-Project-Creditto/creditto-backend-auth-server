package org.creditto.authserver.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.creditto.authserver.auth.dto.LogoutRequest;
import org.creditto.authserver.auth.dto.RefreshTokenRequest;
import org.creditto.authserver.auth.dto.TokenResponse;
import org.creditto.authserver.auth.service.AuthService;
import org.creditto.authserver.global.response.ApiResponseUtil;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.response.SuccessCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/token/refresh")
    public ResponseEntity<BaseResponse<TokenResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpServletRequest
    ) {
        TokenResponse response = authService.refreshToken(request, httpServletRequest);
        return ApiResponseUtil.success(SuccessCode.OK, response);
    }

    @PostMapping("/logout")
    public ResponseEntity<BaseResponse<Void>> logout(@Valid @RequestBody LogoutRequest request) {
        authService.logout(request);
        return ApiResponseUtil.success(SuccessCode.OK);
    }
}
