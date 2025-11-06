package org.creditto.authserver.certificate.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.utils.CertificateEncryptionUtil;
import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.certificate.repository.CertificateRepository;
import org.creditto.authserver.user.entity.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PrivateKey;

import static org.creditto.authserver.global.response.error.ErrorMessage.ENTITY_NOT_FOUND;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CertificateService {

    private final CertificateRepository certificateRepository;
    private final CertificateEncryptionUtil encryptionUtil;

    @Transactional
    public Certificate authenticateCertificate(String certificateSerial, String simplePassword) {
        Certificate certificate = certificateRepository.findBySerialNumber(certificateSerial)
                .orElseThrow(() -> new IllegalArgumentException(ENTITY_NOT_FOUND));

        User user = certificate.getUser();

        // 인증서 유효성 검증

        try {
            PrivateKey privateKey = encryptionUtil.decryptPrivateKey(
                    certificate.getPrivateKey(), simplePassword, user.getSimplePasswordSalt()
            );

            return certificate;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
