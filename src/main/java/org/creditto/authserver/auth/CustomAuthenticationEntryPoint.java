package org.creditto.authserver.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.response.error.ErrorBaseCode;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
// 미인증 사용자에 대한 응답처리
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        handleException(response, authException);
    }

    private void handleException(HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        ErrorBaseCode errorCode = getExceptionType(authenticationException);
        setResponse(response, errorCode);
    }

    private void setResponse(HttpServletResponse response, ErrorBaseCode errorBaseCode) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
        response.setStatus(errorBaseCode.getHttpStatus().value());

        BaseResponse<?> errorResponse = BaseResponse.of(
                errorBaseCode.getCode(),
                errorBaseCode.getMessage()
        );

        PrintWriter writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(errorResponse));
    }

    private ErrorBaseCode getExceptionType(AuthenticationException authenticationException) {
        log.warn("인증 실패 : Type[{}], Message[{}]", authenticationException.getClass().getSimpleName(), authenticationException.getMessage());

        // InvalidBearerTokenException 처리 (JWT 토큰 검증 실패)
        if (authenticationException instanceof InvalidBearerTokenException) {
            log.error("유효하지 않은 Bearer 토큰: {}", authenticationException.getMessage());
            return ErrorBaseCode.EXPIRED_TOKEN;
        }

        // OAuth2AuthenticationException 처리
        if (authenticationException instanceof OAuth2AuthenticationException auth2AuthenticationException) {
            OAuth2Error error = auth2AuthenticationException.getError();
            String oauthErrorCode = error.getErrorCode();

            log.error("OAuth2 인증 실패 - error: {}, description: {}", oauthErrorCode, error.getDescription());

            return switch (oauthErrorCode) {
                case OAuth2ErrorCodes.INVALID_CLIENT -> {
                    log.warn("OAUTH2 ERROR : INVALID CLIENT");
                    yield ErrorBaseCode.OAUTH_INVALID_CLIENT_CREDENTIALS;
                }
                case OAuth2ErrorCodes.UNAUTHORIZED_CLIENT -> {
                    log.warn("OAUTH2 ERROR : UNAUTHORIZED CLIENT");
                    yield ErrorBaseCode.OAUTH_UNAUTHORIZED;
                }
                case OAuth2ErrorCodes.INVALID_GRANT -> {
                    log.warn("OAUTH2 ERROR : INVALID GRANT TYPE");
                    yield ErrorBaseCode.OAUTH_INVALID_GRANT_TYPE;
                }
                default -> {
                    log.warn("OAUTH2 ERROR : {}", oauthErrorCode);
                    yield ErrorBaseCode.OAUTH_DEFAULT_UNAUTHORIZED;
                }
            };
        }

        // 기타 인증 실패
        return ErrorBaseCode.UNAUTHORIZED;
    }
}
