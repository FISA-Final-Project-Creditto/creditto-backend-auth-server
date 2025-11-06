package org.creditto.authserver.auth.constants;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public abstract class CustomGrantType {

    public static final AuthorizationGrantType CERTIFICATE = new AuthorizationGrantType(Constants.CERTIFICATE);
}
