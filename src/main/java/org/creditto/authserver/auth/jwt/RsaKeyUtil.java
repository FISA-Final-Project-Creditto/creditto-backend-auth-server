package org.creditto.authserver.auth.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.creditto.authserver.auth.constants.AlgorithmConstants.RSA;
import static org.creditto.authserver.auth.constants.Constants.*;

@Component
@RequiredArgsConstructor
public class RsaKeyUtil {

    private final RsaKeyProperties rsaKeyProperties;

    public RSAPublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        byte[] decodedKey = getDecodedKeyBytes(rsaKeyProperties.publicKeyPath(), PUBLIC_KEY_BEGIN, PUBLIC_KEY_END);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public RSAPrivateKey getPrivateKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory keyFactory = KeyFactory.getInstance(RSA);
        byte[] decodedKey = getDecodedKeyBytes(rsaKeyProperties.privateKeyPath(), PRIVATE_KEY_BEGIN, PRIVATE_KEY_END);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    private byte[] getDecodedKeyBytes(Resource keyResource, String beginMarker, String endMarker) throws IOException {
        String key = new String(keyResource.getInputStream().readAllBytes());

        String pem = key
                .replace(beginMarker, "")
                .replace(endMarker, "")
                .replaceAll("\\s+", "");

        return Base64.getDecoder().decode(pem);
    }
}
