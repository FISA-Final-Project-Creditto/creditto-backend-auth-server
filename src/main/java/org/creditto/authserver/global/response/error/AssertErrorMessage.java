package org.creditto.authserver.global.response.error;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class AssertErrorMessage {

    public static final String AUTHORIZATION_REPOSITORY_NULL = "AuthorizationRepository는 null일 수 없습니다.";
    public static final String REGISTERED_CLIENT_REPOSITORY_NULL = "registeredClientRepository는 null일 수 없습니다.";
    public static final String AUTHORIZATION_NULL = "authorization는 null일 수 없습니다.";
    public static final String ID_EMPTY = "id가 비어있습니다.";
    public static final String TOKEN_EMPTY = "token이 비어있습니다.";

    public static final String JSON_PARSE_FAILED = "직렬화 실패";
    public static final String JSON_WRITE_FAILED = "역직렬화 실패";

    public static final String REGISTERED_CLIENT_NOT_FOUND_IN_REPO = "해당 Client를 찾을 수 없습니다.";
}
