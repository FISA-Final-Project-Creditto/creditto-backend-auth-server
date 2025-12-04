package org.creditto.authserver.auth.token.exception;

import org.creditto.authserver.global.response.error.ErrorMessage;

public class InvalidRefreshTokenException extends RuntimeException {
    public InvalidRefreshTokenException() {
        super(ErrorMessage.INVALID_REFRESH_TOKEN);
    }

    public InvalidRefreshTokenException(String message) {
        super(message);
    }
}
