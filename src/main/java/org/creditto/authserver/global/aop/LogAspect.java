package org.creditto.authserver.global.aop;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.annotation.Pointcut;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.util.MaskingUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.validation.BindingResult;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Arrays;

@Aspect
@Slf4j
@Component
@RequiredArgsConstructor
public class LogAspect {

    private final ObjectMapper objectMapper;

    @Pointcut("execution(* org.creditto.authserver..controller..*(..))")
    private void onRequest() {
    }

    @Pointcut("execution(* org.creditto.authserver..service..*(..))")
    private void onService() {
    }

    @Around("onRequest()")
    public Object logRequestAndResponse(final ProceedingJoinPoint joinPoint) throws Throwable {
        final ServletRequestAttributes requestAttributes = getRequestAttributes();
        final HttpServletRequest request = requestAttributes != null ? requestAttributes.getRequest() : null;

        final String className = joinPoint.getTarget().getClass().getSimpleName();
        final String requestUri = request != null ? request.getRequestURI() : joinPoint.getSignature().toShortString();
        final String method = request != null ? request.getMethod() : "N/A";
        final String requestIp = request != null ? request.getRemoteAddr() : "N/A";

        log.info("[{}] Request IP : {} | Request URI : {} | Request Method : {}", className, requestIp, requestUri, method);

        final Object[] sanitizedArgs = Arrays.stream(joinPoint.getArgs())
                .filter(arg -> !(arg instanceof HttpServletRequest))
                .filter(arg -> !(arg instanceof HttpServletResponse))
                .filter(arg -> !(arg instanceof BindingResult))
                .toArray();

        if (sanitizedArgs.length > 0) {
            final String argsAsString = MaskingUtil.maskSensitiveData(serialize(sanitizedArgs));
            log.info("[{}] {} {} - RequestBody: {}", className, method, requestUri, argsAsString);
        }

        try {
            final Object result = joinPoint.proceed();
            Object responseBody = result;
            if (result instanceof ResponseEntity<?> responseEntity) {
                responseBody = responseEntity.getBody();
            }
            final Object dataForLog = responseBody instanceof BaseResponse<?> baseResponse
                    ? baseResponse.getData()
                    : responseBody;
            final String responseAsString = MaskingUtil.maskSensitiveData(serialize(dataForLog));
            log.info("[{}] {} {} - ResponseData: {}", className, method, requestUri, responseAsString);
            return result;
        } catch (Throwable e) {
            log.error("[{}] {} {} - Exception occurred : {}", className, method, requestUri, e.getMessage());
            throw e;
        }
    }

    @Before("onService()")
    public void beforeServiceLog(final JoinPoint joinPoint) {
        final String className = joinPoint.getTarget().getClass().getSimpleName();
        final String methodName = joinPoint.getSignature().getName();
        final Object[] args = joinPoint.getArgs();

        log.info("[{}] {}() called", className, methodName);

        if (args.length > 0) {
            final String params = MaskingUtil.maskSensitiveData(serialize(args));
            log.debug("[{}] Parameters: {}", className, params);
        }
    }

    private ServletRequestAttributes getRequestAttributes() {
        final RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes instanceof ServletRequestAttributes servletRequestAttributes) {
            return servletRequestAttributes;
        }
        return null;
    }

    private String serialize(final Object value) {
        if (value == null) {
            return "null";
        }

        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            log.debug("직렬화 실패: {}", e.getMessage());
            return String.valueOf(value);
        }
    }
}
