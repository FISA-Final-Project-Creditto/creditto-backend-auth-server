package org.creditto.authserver.auth.utils;

import org.creditto.authserver.auth.constants.AlgorithmConstants;
import org.creditto.authserver.global.exception.CustomException;
import org.creditto.authserver.global.exception.InvalidSimplePasswordException;
import org.creditto.authserver.global.response.error.ErrorMessage;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.creditto.authserver.auth.constants.AlgorithmConstants.*;

// 인정서 암호화 Util
@Component
public class CertificateEncryptionUtil {

    /**
     * RSA 키 쌍 생성 (2048 비트)
     * @return 생성된 RSA 키 쌍
     */
    public KeyPair generateRSAKeyPair() {

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomException(e.getMessage());
        }
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
        String extendedSimplePassword = null;
        try {
            extendedSimplePassword = extendSimplePassword(simplePassword);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomException(e.getMessage());
        }

        // AES
        byte[] encrypted = AESUtil.encrypt(privateKeyEncoded, extendedSimplePassword, salt);

        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 개인키 복호화 (By 간편비밀번호)
     * @param encryptedKey 암호화된 개인키 (Base64)
     * @param simplePassword 간편비밀번호
     * @param salt 복호화에 사용될 salt
     * @return 복호화된 PrivateKey
     */
    public PrivateKey decryptPrivateKey(String encryptedKey, String simplePassword, String salt) throws GeneralSecurityException{
        byte[] encrypted = Base64.getDecoder().decode(encryptedKey);

        // 간편 비밀번호 암호화
        String extendedSimplePassword = extendSimplePassword(simplePassword);

        try {
            byte[] decrypted = AESUtil.decrypt(encrypted, extendedSimplePassword, salt);

            KeyFactory keyFactory = KeyFactory.getInstance(RSA);

            return keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(decrypted)
            );
        } catch (Exception e) {
            throw new InvalidSimplePasswordException(ErrorMessage.INVALID_SIMPLE_PASSWORD);
        }
    }

    /**
     * RSA 키쌍 검증 (개인키-공개키 매칭 확인)
     * @param privateKey 검증할 개인키
     * @param publicKey 검증할 공개키
     * @return 키쌍이 일치하면 true
     */
    public boolean verifyKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        try {
            // 테스트 메시지로 서명 검증
            String testMessage = "KEY_PAIR_VERIFICATION";

            // 개인키로 서명
            String signature = sign(privateKey, testMessage);

            // 공개키로 검증
            return verify(publicKey, testMessage, signature);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 인증서 public키 Encoding
     * @param publicKey pulbicKey
     * @return encoding된 publicKey
     */
    public String encodePublicKey(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * 인증서 public키 Decoding
     * @param encodedKey encoding된 publicKey
     * @return decoding된 publicKey
     */
    public PublicKey decodePublicKey(String encodedKey) throws InvalidKeySpecException {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(AlgorithmConstants.RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomException(e.getMessage());
        }
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * 전자서명
     * @param privateKey 전자서명에 사용할 개인키
     * @param data 인증서
     * @return 서명
     */
    public String sign(PrivateKey privateKey, String data) throws GeneralSecurityException {
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
    public boolean verify(PublicKey publicKey, String data, String signatureStr) throws GeneralSecurityException{
        Signature signature = Signature.getInstance(SHA256_WITH_RSA);
        signature.initVerify(publicKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        byte[] signBytes = Base64.getDecoder().decode(signatureStr);
        return signature.verify(signBytes);
    }

    private String extendSimplePassword(String simplePassword) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(SHA256);
        byte[] digested = messageDigest.digest(simplePassword.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(digested);
    }
}
