package org.creditto.authserver.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

@ConfigurationProperties(prefix = "auth.jwt")
public record RsaKeyProperties(
        Resource privateKeyPath,
        Resource publicKeyPath
) {}
