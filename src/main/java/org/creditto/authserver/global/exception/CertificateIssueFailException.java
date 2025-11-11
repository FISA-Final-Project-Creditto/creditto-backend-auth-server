package org.creditto.authserver.global.exception;

public class CertificateIssueFailException extends RuntimeException {
    public CertificateIssueFailException(String message) {
        super(message);
    }
}
