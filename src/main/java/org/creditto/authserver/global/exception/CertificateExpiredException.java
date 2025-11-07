package org.creditto.authserver.global.exception;

public class CertificateExpiredException extends RuntimeException {
    public CertificateExpiredException(String message) {
        super(message);
    }
}