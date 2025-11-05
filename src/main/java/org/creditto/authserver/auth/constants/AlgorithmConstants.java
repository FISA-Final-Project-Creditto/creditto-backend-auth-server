package org.creditto.authserver.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public abstract class AlgorithmConstants {

    public static final String RSA = "RSA";
    public static final String SHA256 = "SHA-256";
    public static final String SHA256_WITH_RSA = "SHA256withRSA";
}