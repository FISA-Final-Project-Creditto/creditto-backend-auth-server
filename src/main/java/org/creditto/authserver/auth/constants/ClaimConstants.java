package org.creditto.authserver.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ClaimConstants {

    public static final String USER_ID = "user_id";
    public static final String EXTERNAL_USER_ID = "externalUserId";
    public static final String USERNAME = "userName";
    public static final String ROLES = "roles";
    public static final String NAME = "name";
    public static final String USER_PHONE_NO= "userPhoneNo";
    public static final String CERT_ID = "certificateId";
    public static final String CERT_SERIAL = "certificate_serial";
    public static final String CERT_SERIAL_CAMEL = "certificateSerial";
    public static final String AUTH_METHOD = "auth_method";
    public static final String AUTHORITIES = "authorities";
}
