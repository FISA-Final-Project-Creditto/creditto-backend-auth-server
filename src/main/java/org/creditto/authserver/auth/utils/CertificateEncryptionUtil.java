package org.creditto.authserver.auth.utils;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.creditto.authserver.auth.constants.AlgorithmConstants.RSA;
import static org.creditto.authserver.auth.constants.AlgorithmConstants.SHA256_WITH_RSA;

// 인정서 암호화 Util
@Component
public class CertificateEncryptionUtil {

    /**
     * RSA 키 쌍 생성 (2048 비트)
     * @return 생성된 RSA 키 쌍
     * @throws NoSuchAlgorithmException 알고리즘 미발견 예외
     */
    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 개인키 암호화 (By 간편비밀번호)
     * @param privateKey RSA 개인키
     * @param simplePassword 간편비밀번호
     * @param salt 암호화에 사용될 salt
     * @return Base64로 인코딩된 암호
     */
    public String encryptPrivateKey(PrivateKey privateKey, String simplePassword, String salt) {
        byte[] privateKeyEncoded = privateKey.getEncoded();

        // 간편비밀번호 암호화

        // AES
        byte[] encrypted = AESUtil.encrypt(privateKeyEncoded, simplePassword, salt);

        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 개인키 복호화 (By 간편비밀번호)
     * @param encryptedKey 암호화된 개인키 (Base64)
     * @param simplePassword 간편비밀번호
     * @param salt 복호화에 사용될 salt
     * @return 복호화된 PrivateKey
     */
    public PrivateKey decryptPrivateKey(String encryptedKey, String simplePassword, String salt) throws Exception{
        byte[] encrypted = Base64.getDecoder().decode(encryptedKey);

        // 간편 비밀번호 암호화
        byte[] decrypted = AESUtil.decrypt(encrypted, simplePassword, salt);

        KeyFactory keyFactory = KeyFactory.getInstance(RSA);

        return keyFactory.generatePrivate(
                new PKCS8EncodedKeySpec(decrypted)
        );
    }

    /**
     * 전자서명
     * @param privateKey 전자서명에 사용할 개인키
     * @param data 인증서
     * @return 서명
     */
    public String sign(PrivateKey privateKey, String data) throws Exception {
        Signature signature = Signature.getInstance(SHA256_WITH_RSA);
        signature.initSign(privateKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signBytes);
    }

    /**
     * 전자서명 검증
     * @param publicKey 전자서명을 검증할 공개키
     * @param data 인증서
     * @param signatureStr 서명
     * @return 검증결과
     */
    public boolean verify(PublicKey publicKey, String data, String signatureStr) throws Exception{
        Signature signature = Signature.getInstance(SHA256_WITH_RSA);
        signature.initVerify(publicKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = Base64.getDecoder().decode(signatureStr);
        return signature.verify(signBytes);
    }
}
