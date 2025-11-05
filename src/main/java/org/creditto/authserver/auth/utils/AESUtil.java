package org.creditto.authserver.auth.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AESUtil {

    /**
     * 바이트 배열 암호화 (AES-256)
     * @param input 암호화할 데이터
     * @param salt 암호화에 필요한 salt 값
     * @return 암호화된 바이트배열
     */
    public static byte[] encrypt(byte[] input, String password, String salt) {
        BytesEncryptor encryptor = Encryptors.stronger(password, salt);
        return encryptor.encrypt(input);
    }

    /**
     * 바이트 배열 복호화 (AES-256)
     * @param encryptedInput 암호화된 바이트배열
     * @param salt 복호화에 필요한 salt 값 (암호화 salt 값과 동일해야 함)
     * @return 복호화된 데이터
     */
    public static byte[] decrypt(byte[] encryptedInput, String password, String salt) {
        BytesEncryptor encryptor = Encryptors.stronger(password, salt);
        return encryptor.decrypt(encryptedInput);
    }

    /**
     * 암호화 및 복호화에 필요한 salt 생성
     * @return random salt 값
     */
    public static String generateSalt() {
        return KeyGenerators.string().generateKey();
    }
}
