package org.creditto.authserver.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ClaimConstants {

    public static final String USER_ID = "user_id";
    public static final String NAME = "name";
    public static final String CERT_SERIAL = "certificate_serial";
    public static final String AUTH_METHOD = "auth_method";
    public static final String AUTHORITIES = "authorities";
}
