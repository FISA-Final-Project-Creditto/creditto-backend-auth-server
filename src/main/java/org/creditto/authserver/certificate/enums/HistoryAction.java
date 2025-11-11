package org.creditto.authserver.certificate.enums;

public enum HistoryAction {
    READ("조회"),
    ISSUE("발급"),
    DELETE("삭제"),
    UPDATE("수정"),
    AUTHENTICATION("인증");

    private final String action;

    HistoryAction(String action) {this.action = action;}
}
