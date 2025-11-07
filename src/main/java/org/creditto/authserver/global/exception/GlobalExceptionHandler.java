package org.creditto.authserver.global.exception;

import com.fasterxml.jackson.databind.JsonMappingException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.global.response.ApiResponseUtil;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.response.error.ErrorBaseCode;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.io.UnsupportedEncodingException;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * 400 - MethodArgumentNotValidException
     * 예외 내용 : @Valid 유효성 검사 오류 (Request Body)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<BaseResponse<?>> handleMethodArgumentNotValidException(final MethodArgumentNotValidException e) {
        final String errorMessage = e.getBindingResult().getAllErrors().stream()
                .map(error -> {
                    if (error instanceof FieldError fe) {
                        return "%s는(은) %s".formatted(fe.getField(), fe.getDefaultMessage());
                    } else {
                        return "%s는(은) %s".formatted(error.getObjectName(), error.getDefaultMessage());
                    }
                })
                .collect(Collectors.joining("\n"));
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.INVALID_REQUEST_BODY, errorMessage);
    }

    /**
     * 400 - MissingServletRequestParameterException
     * 예외 내용 : 필수 파라미터가 존재하지 않음
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<BaseResponse<?>> handleMissingServletRequestParameterException(final MissingServletRequestParameterException e) {
        final String errorMessage = "누락 파라미터 : " + e.getParameterName();
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.MISSING_PARAM, errorMessage);
    }

    /**
     * 400 - HttpMessageNotReadableException
     * 예외 내용 : JSON 바인딩 오류 || @RequestBody 필수 값 오류 || @RequestBody 데이터 자료형 오류 || 데이터 포맷 오류
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<BaseResponse<?>> handleHttpMessageNotReadableException(final HttpMessageNotReadableException e) {
        logWarn(e);
        // JSON 매핑 오류
        if (e.getCause() instanceof JsonMappingException jsonMappingException) {

            String errorMessage = jsonMappingException.getPath().stream()
                    .map(ref -> String.format("잘못된 필드 값 : '%s'", ref.getFieldName()))
                    .collect(Collectors.joining("\n"));

            return ApiResponseUtil.failure(ErrorBaseCode.NOT_READABLE, errorMessage);
        } else {
            return ApiResponseUtil.failure(ErrorBaseCode.NOT_READABLE);
        }
    }

    /**
     * 400 - IllegalArgumentException
     * 예외 내용 : 잘못된 인자값 전달로 인한 오류
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<BaseResponse<?>> handleIllegalArgumentException(final IllegalArgumentException e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.BAD_REQUEST_ILLEGALARGUMENTS, e.getMessage());
    }

    /**
     * 401 - InvalidSimplePasswordException
     * 예외 내용 : 잘못된 간편비밀번호
     */
    @ExceptionHandler(InvalidSimplePasswordException.class)
    public ResponseEntity<BaseResponse<?>> handleInvalidSimplePassword(final InvalidSimplePasswordException e) {
        log.error("잘못된 간편비밀번호: {}", e.getMessage());
        return ApiResponseUtil.failure(ErrorBaseCode.INVALID_SIMPLE_PASSWORD, e.getMessage());
    }

    /**
     * 401 - OAuth2AuthenticationException
     * 예외 내용: OAuth2 인증 실패
     */
    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<BaseResponse<?>> handleOAuth2AuthenticationException(final OAuth2AuthenticationException e) {
        OAuth2Error error = e.getError();
        log.error("OAuth2 인증 실패 - error: {}, description: {}", error.getErrorCode(), error.getDescription());

        // OAuth2 에러 코드에 따른 분기 처리
        return switch (error.getErrorCode()) {
            case "invalid_client" -> ApiResponseUtil.failure(ErrorBaseCode.OAUTH_INVALID_CLIENT_CREDENTIALS, error.getDescription());
            case "invalid_grant" -> ApiResponseUtil.failure(ErrorBaseCode.OAUTH_INVALID_GRANT_TYPE, error.getDescription());
            case "unauthorized_client" -> ApiResponseUtil.failure(ErrorBaseCode.OAUTH_UNAUTHORIZED, error.getDescription());
            default -> ApiResponseUtil.failure(ErrorBaseCode.OAUTH_DEFAULT_UNAUTHORIZED, error.getDescription());
        };
    }

    /**
     * 401 - InvalidBearerTokenException
     * 예외 내용: 유효하지 않은 Bearer 토큰
     */
    @ExceptionHandler(InvalidBearerTokenException.class)
    public ResponseEntity<BaseResponse<?>> handleInvalidBearerTokenException(final InvalidBearerTokenException e) {
        log.error("유효하지 않은 Bearer 토큰: {}", e.getMessage());
        return ApiResponseUtil.failure(ErrorBaseCode.EXPIRED_TOKEN, e.getMessage());
    }

    /**
     * 403 - AccessDeniedException
     * 예외 내용: 사용자가 허가되지 않은 자원에 접근할 때 발생
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<BaseResponse<?>> handleAccessDeniedException(final AccessDeniedException e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.FORBIDDEN, e.getMessage());
    }

    /**
     * 404 - EntityNotFoundException
     * 예외 내용 : 리소스에 대한 엔티티를 찾을 수 없는 오류
     */
    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<BaseResponse<?>> handleEntityNotFoundException(final EntityNotFoundException e) {
        return ApiResponseUtil.failure(ErrorBaseCode.NOT_FOUND_ENTITY, e.getMessage());
    }

    /**
     * 404 - CertificateNotFoundException
     * 예외 내용 : 인증서를 찾을 수 없음
     */
    @ExceptionHandler(CertificateNotFoundException.class)
    public ResponseEntity<BaseResponse<?>> handleCertificateNotFound(final CertificateNotFoundException e) {
        log.error("인증서를 찾을 수 없음: {}", e.getMessage());
        return ApiResponseUtil.failure(ErrorBaseCode.CERTIFICATE_NOT_FOUND, e.getMessage());
    }

    /**
     * 404 - NoHandlerFoundException
     * 예외 내용 : 잘못된 api로 요청했을 때 발생
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<BaseResponse<?>> handleNoHandlerFoundException(final NoHandlerFoundException e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.NOT_FOUND_API);
    }

    /**
     * 404 - NoResourceFoundException
     * 예외 내용 : 잘못된 엔드포인트로 요청했을 때 발생
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<BaseResponse<?>> handleNoResourceFoundException(final NoResourceFoundException e) {
        return ApiResponseUtil.failure(ErrorBaseCode.NOT_FOUND_API);
    }

    /**
     * 405 - HttpRequestMethodNotSupportedException
     * 예외 내용 : 잘못된 HTTP METHOD로 요청했을 때 발생
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<BaseResponse<?>> handleHttpRequestMethodNotSupportedException(final HttpRequestMethodNotSupportedException e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.METHOD_NOT_ALLOWED);
    }

    /**
     * 410 - CertificateExpiredException
     * 예외 내용 : 인증서 만료
     */
    @ExceptionHandler(CertificateExpiredException.class)
    public ResponseEntity<BaseResponse<?>> handleCertificateExpired(final CertificateExpiredException e) {
        log.error("인증서 만료: {}", e.getMessage());
        return ApiResponseUtil.failure(ErrorBaseCode.CERTIFICATE_EXPIRED, e.getMessage());
    }

    /**
     * 409 - DataIntegrityViolationException
     * 예외 내용 : DB 제약조건 위반 에러 (FK/NOT NULL 등)
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<BaseResponse<?>> handleDataIntegrity(DataIntegrityViolationException e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.DB_CONFLICT);
    }

    /**
     * 409, 500 - TransactionSystemException, ConstraintViolationException
     * 예외 내용 : 트랜잭션 관련 에러
     */
    @ExceptionHandler(TransactionSystemException.class)
    public ResponseEntity<BaseResponse<?>> handleTx(TransactionSystemException e) {
        logWarn(e);
        Throwable root = NestedExceptionUtils.getMostSpecificCause(e);
        if (root instanceof ConstraintViolationException cve) {
            String errorMessage = cve.getConstraintViolations().stream()
                    .map(v -> v.getPropertyPath() + ": " + v.getMessage())
                    .collect(Collectors.joining("\n"));
            return ApiResponseUtil.failure(ErrorBaseCode.BAD_REQUEST, errorMessage);
        }
        return ApiResponseUtil.failure(ErrorBaseCode.INTERNAL_SERVER_ERROR);
    }

    /**
     * 500 - UrlDecodeException
     * 예외 내용 : URL 디코딩시 에러 발생
     */
    @ExceptionHandler(UnsupportedEncodingException.class)
    public ResponseEntity<BaseResponse<?>> handleUrlDecodeException(final UnsupportedEncodingException e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.URL_DECODE_ERROR);
    }

    /**
     * 500 - ServerError
     * 예외 내용 : 서버 내부 오류
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<BaseResponse<?>> handleServerException(final Exception e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<BaseResponse<?>> handleCustomException(final CustomException e) {
        logWarn(e);
        return ApiResponseUtil.failure(ErrorBaseCode.INTERNAL_SERVER_ERROR);
    }

    private void logWarn(Exception e) {
        log.warn("[{}]: message={}", e.getClass().getSimpleName(), e.getMessage(), e);
    }
}
