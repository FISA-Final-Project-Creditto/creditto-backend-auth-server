package org.creditto.authserver.global.response;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.creditto.authserver.global.response.error.ErrorCode;
import org.springframework.http.ResponseEntity;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ApiResponseUtil {

    public static ResponseEntity<BaseResponse<?>> success(final SuccessCode successCode) {
        return ResponseEntity.status(successCode.getHttpStatus())
                .body(BaseResponse.of(successCode));
    }

    public static <T> ResponseEntity<BaseResponse<?>> success(final SuccessCode successCode, final T data) {
        return ResponseEntity.status(successCode.getHttpStatus())
                .body(BaseResponse.of(successCode, data));
    }

    public static ResponseEntity<BaseResponse<?>> failure(final ErrorCode errorBaseCode) {
        return ResponseEntity.status(errorBaseCode.getHttpStatus())
                .body(BaseResponse.of(errorBaseCode));
    }

    //따로 error message 넣어줄 때, 사용
    public static ResponseEntity<BaseResponse<?>> failure(final ErrorCode errorBaseCode, final String message) {
        return ResponseEntity
                .status(errorBaseCode.getHttpStatus())
                .body(BaseResponse.of(errorBaseCode.getCode(), message));
    }
}
