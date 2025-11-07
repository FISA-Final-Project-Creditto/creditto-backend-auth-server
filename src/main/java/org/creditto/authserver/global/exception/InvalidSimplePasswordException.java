package org.creditto.authserver.global.exception;

public class InvalidSimplePasswordException extends RuntimeException {
    public InvalidSimplePasswordException(String message) {
        super(message);
    }
}