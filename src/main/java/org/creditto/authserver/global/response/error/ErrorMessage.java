package org.creditto.authserver.global.response.error;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ErrorMessage {

    /**
     * NOT FOUND - 조회 실패
     */
    public static final String NOT_DEFINED_VALUE = "정의되지 않은 값입니다.";
    public static final String FAILED_PARSE = "파싱 실패";
    public static final String FAILED_SERIALIZED = "직렬화 실패";

    /**
     * INVALID - 유효하지 않음
     */
    public static final String DUPLICATED_REQUEST = "이미 존재하는 리소스 입니다.";
    public static final String INVALID_TOKEN = "유효하지 않은 토큰입니다.";
    public static final String UNENROLLED_USER = "가입되지 않은 사용자입니다.";

    /**
     * DENIED - 접근 거부
     */
    public static final String ACCESS_DENIED = "권한이 없습니다.";
}
