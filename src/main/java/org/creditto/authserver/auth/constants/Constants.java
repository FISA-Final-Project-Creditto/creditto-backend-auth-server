package org.creditto.authserver.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class Constants {

    public static final String CERTIFICATE = "certificate";
    public static final String STANDARD = "standard";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String SECONDS = "seconds";
    public static final String PUBLIC_KEY_BEGIN = "-----BEGIN PUBLIC KEY-----";
    public static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";
    public static final String PRIVATE_KEY_BEGIN = "-----BEGIN PRIVATE KEY-----";
    public static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";
}
