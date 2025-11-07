package org.creditto.authserver.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.response.error.ErrorBaseCode;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * 인증된 사용자가 권한이 없는 리소스에 접근할 때 처리
 * Spring Security 필터 체인에서 발생하는 AccessDeniedException 처리
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        log.warn("접근 거부 : URI[{}], Message[{}]", request.getRequestURI(), accessDeniedException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(String.valueOf(StandardCharsets.UTF_8));
        response.setStatus(ErrorBaseCode.FORBIDDEN.getHttpStatus().value());

        BaseResponse<?> errorResponse = BaseResponse.of(
                ErrorBaseCode.FORBIDDEN.getCode(),
                ErrorBaseCode.FORBIDDEN.getMessage()
        );

        PrintWriter writer = response.getWriter();
        writer.write(objectMapper.writeValueAsString(errorResponse));
    }
}
