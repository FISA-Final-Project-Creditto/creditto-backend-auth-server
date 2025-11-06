package org.creditto.authserver.global.response;

import org.springframework.http.HttpStatus;

public interface ApiCode {
    HttpStatus getHttpStatus();
    int getCode();
    String getMessage();
}
