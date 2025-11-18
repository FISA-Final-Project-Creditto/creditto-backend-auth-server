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
    public static final String ENTITY_NOT_FOUND = "존재하지 않는 리소스입니다.";
    public static final String USER_NOT_FOUND = "사용자를 찾을 수 없습니다.";
    public static final String CERTIFICATE_NOT_FOUND = "인증서를 찾을 수 없습니다.";

    /**
     * INVALID - 유효하지 않음
     */
    public static final String DUPLICATED_REQUEST = "이미 존재하는 리소스 입니다.";
    public static final String INVALID_TOKEN = "유효하지 않은 토큰입니다.";
    public static final String UNENROLLED_USER = "가입되지 않은 사용자입니다.";
    public static final String INVALID_RESOURCE = "유효하지 않은 리소스입니다.";
    public static final String EXPIRED_RESOURCE = "만료된 리소스입니다.";
    public static final String INVALID_SIMPLE_PASSWORD = "간편비밀번호가 일치하지 않습니다.";
    public static final String SIMPLE_PASSWORD_LENGTH_INVALID = "간편비밀번호는 6자리여야 합니다.";
    public static final String SIMPLE_PASSWORD_FORMAT_INVALID = "간편비밀번호는 숫자만 입력 가능합니다.";
    public static final String SIMPLE_PASSWORD_SEQUENTIAL = "연속된 숫자는 사용할 수 없습니다.";
    public static final String SIMPLE_PASSWORD_REPEATED = "동일한 숫자 반복은 사용할 수 없습니다.";
    public static final String INVALID_USER_INFO = "사용자 정보가 일치하지 않습니다.";
    public static final String CERTIFICATE_NOT_ACTIVE = "인증서가 활성 상태가 아닙니다.";
    public static final String CERTIFICATE_EXPIRED = "인증서가 만료되었습니다.";
    public static final String CERTIFICATE_AUTH_FAILED = "인증서 인증에 실패했습니다.";
    public static final String SIMPLE_PASSWORD_CHANGE_FAILED = "간편비밀번호 변경에 실패했습니다.";
    public static final String FAILED_LOAD_RSA = "RSA 키 조회에 실패했습니다.";
    public static final String INVALID_USERNAME = "사용자 이름 정보가 일치하지 않습니다.";
    public static final String INVALID_USER_BIRTH_DATE = "사용자 생년월일 정보가 일치하지 않습니다.";
    public static final String INVALID_USER_EX_ID = "사용자 ID 정보가 일치하지 않습니다.";

    /**
     * DENIED - 접근 거부
     */
    public static final String ACCESS_DENIED = "권한이 없습니다.";

    /**
     * OAUTH2 - OAuth2 관련 오류
     */
    public static final String INVALID_CLIENT = "유효하지 않은 클라이언트입니다.";
    public static final String TOKEN_GENERATION_FAILED = "토큰 생성에 실패했습니다.";
    public static final String CLIENT_NOT_FOUND = "클라이언트를 찾을 수 없습니다.";

    /**
     * CONFLICT
     */
    public static final String CERTIFICATE_EXISTS = "인증서가 이미 존재합니다.";
}
