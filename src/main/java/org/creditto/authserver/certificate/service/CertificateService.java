package org.creditto.authserver.certificate.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.utils.AESUtil;
import org.creditto.authserver.auth.utils.CertificateEncryptionUtil;
import org.creditto.authserver.certificate.CertificateStatus;
import org.creditto.authserver.certificate.dto.CertificateIssueRequest;
import org.creditto.authserver.certificate.dto.CertificateIssueResponse;
import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.certificate.entity.CertificateUsageHistory;
import org.creditto.authserver.global.exception.CertificateExpiredException;
import org.creditto.authserver.global.exception.CertificateNotFoundException;
import org.creditto.authserver.global.exception.InvalidSimplePasswordException;
import org.creditto.authserver.certificate.repository.CertificateRepository;
import org.creditto.authserver.certificate.repository.CertificateUsageHistoryRepository;
import org.creditto.authserver.user.entity.User;
import org.creditto.authserver.user.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.creditto.authserver.global.response.error.ErrorMessage.*;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class CertificateService {

    private static final int CERTIFICATE_VALIDITY_YEARS = 3;

    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateUsageHistoryRepository certificateUsageHistoryRepository;
    private final CertificateEncryptionUtil encryptionUtil;

    /**
     * 인증서 발급
     * @param request 인증서 발급을 위한 사용자 정보 & 간편비밀번호
     * @return 인증서 발급 정보
     */
    @Transactional
    public CertificateIssueResponse issueCertificate(CertificateIssueRequest request) {
        // 사용자 검증
        User user = getAndValidateUser(request);

        // 간편비밀번호 유효성 검증
        validateSimplePassword(request.simplePassword());

        // RSA 키 쌍 생성
        KeyPair keyPair = encryptionUtil.generateRSAKeyPair();

        // 인증서별 고유 SALT 생성
        String certificateSalt = AESUtil.generateSalt();

        // 개인키를 간편비밀번호로 암호화
        String encryptedPrivateKey = encryptionUtil.encryptPrivateKey(
                keyPair.getPrivate(),
                request.simplePassword(),
                certificateSalt
        );

        // 인증서 생성
        Certificate certificate = createCertificate(keyPair, user, encryptedPrivateKey, certificateSalt);

        certificateRepository.save(certificate);

        log.info("인증서 발급 완료 - 사용자: {}, 일련번호: {}", user.getName(), certificate.getSerialNumber());

        return CertificateIssueResponse.from(certificate);
    }

    /**
     * 인증서 기반 인증
     * @param certificateSerial 인증서 Serial Number
     * @param simplePassword 간편 비밀번호
     * @return 인증서 (Entity)
     */
    @Transactional
    public Certificate authenticateWithCertificate(String certificateSerial, String simplePassword) {
        // 인증서 조회
        Certificate certificate = certificateRepository.findBySerialNumber(certificateSerial)
                .orElseThrow(() -> new CertificateNotFoundException(CERTIFICATE_NOT_FOUND + ": " + certificateSerial));

        User user = certificate.getUser();

        validateCertificate(certificate);

        try {
            // 키쌍 검증
            if (verifyCertificateKeyPair(simplePassword, certificate)) {
                log.info("인증서 인증 성공 - 사용자: {}, 인증서: {}", user.getName(), certificateSerial);
                return certificate;
            } else {
                log.error("인증서 키쌍 검증 실패 - 인증서: {}", certificateSerial);
                throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
            }
        } catch (InvalidSimplePasswordException e) {
            log.error("간편비밀번호 불일치 - 인증서: {}", certificateSerial);
            throw e;
        } catch (Exception e) {
            log.error("인증서 인증 실패 - 인증서: {}, 사유: {}", certificateSerial, e.getMessage());
            throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
        }
    }

    /**
     * 인증서 사용기록 저장
     * @param certificate
     * @param action
     * @param success
     * @param failureReason
     * @param ipAddress
     * @param userAgent
     */
    private void recordUsageHistory(Certificate certificate,
                                    String action,
                                    boolean success,
                                    String failureReason,
                                    String ipAddress,
                                    String userAgent) {
        CertificateUsageHistory history = CertificateUsageHistory.builder()
                .certificate(certificate)
                .action(action)
                .success(success)
                .failureReason(failureReason)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        certificateUsageHistoryRepository.save(history);

        log.debug("인증서 사용 이력 기록 - 인증서: {}, 작업: {}, 성공: {}",
                certificate.getSerialNumber(), action, success);
    }


    public List<CertificateUsageHistory> getCertificateHistory(String serialNumber, String simplePassword) {
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new CertificateNotFoundException(CERTIFICATE_NOT_FOUND + ": " + serialNumber));

        try {
            if (verifyCertificateKeyPair(simplePassword, certificate)) {
                return certificateUsageHistoryRepository.findByCertificate(certificate);
            } else {
                throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
        }
    }

    /**
     * 사용자 인증서 목록 조회
     */
    public List<Certificate> getUserCertificates(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        return certificateRepository.findByUser(user);
    }

    /**
     * 활성 인증서 목록 조회
     */
    public List<Certificate> getActiveCertificates(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        return certificateRepository.findByUserAndStatus(user, CertificateStatus.ACTIVE);
    }

    /**
     * 인증서 폐기
     */
    @Transactional
    public void revokeCertificate(String serialNumber, String simplePassword, String reason) {
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new CertificateNotFoundException(CERTIFICATE_NOT_FOUND + ": " + serialNumber));
        try {
            if (verifyCertificateKeyPair(simplePassword, certificate)) {
                certificate.revoke(reason);
                certificateRepository.save(certificate);
                log.info("인증서 폐기 완료 - 일련번호: {}, 사유: {}", serialNumber, reason);
            } else {
                throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
        }
    }

    /**
     * 인증서 상세 조회
     */
    public Certificate getCertificate(String serialNumber, String simplePassword) {
        Certificate certificate = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new CertificateNotFoundException(CERTIFICATE_NOT_FOUND + ": " + serialNumber));
        try {
            if (verifyCertificateKeyPair(simplePassword, certificate)) {
                return certificate;
            } else {
                throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
            }
        } catch (GeneralSecurityException e) {
            throw new InvalidSimplePasswordException(CERTIFICATE_AUTH_FAILED);
        }
    }

    /**
     * 활성 인증서 개수 조회
     */
    public long countActiveCertificates(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        return certificateRepository.countByUserAndStatus(user, CertificateStatus.ACTIVE);
    }

    /**
     * 인증서 갱신
     */
    @Transactional
    public CertificateIssueResponse renewCertificate(String oldSerialNumber, String simplePassword) {
        // 기존 인증서 조회 및 검증
        Certificate oldCertificate = certificateRepository.findBySerialNumber(oldSerialNumber)
                .orElseThrow(() -> new CertificateNotFoundException(CERTIFICATE_NOT_FOUND + ": " + oldSerialNumber));

        User user = oldCertificate.getUser();

        // 새 RSA 키 쌍 생성
        KeyPair keyPair = encryptionUtil.generateRSAKeyPair();

        // 새 인증서별 SALT 생성
        String certificateSalt = AESUtil.generateSalt();

        // 개인키를 간편비밀번호로 암호화
        String encryptedPrivateKey = encryptionUtil.encryptPrivateKey(
                keyPair.getPrivate(),
                simplePassword,
                certificateSalt
        );

        Certificate newCertificate = createCertificate(keyPair, user, encryptedPrivateKey, certificateSalt);

        certificateRepository.save(newCertificate);

        // 기존 인증서 폐기
        oldCertificate.revoke("인증서 갱신");
        certificateRepository.save(oldCertificate);

        log.info("인증서 갱신 완료 - 사용자: {}, 기존: {}, 신규: {}",
                user.getName(), oldSerialNumber, newCertificate.getSerialNumber());

        return CertificateIssueResponse.from(newCertificate);
    }

    private Certificate createCertificate(KeyPair keyPair, User user, String encryptedPrivateKey, String certificateSalt) {
        String publicKey = encryptionUtil.encodePublicKey(keyPair.getPublic());

        // 8. 인증서 생성
        String serialNumber = UUID.randomUUID().toString();
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiresAt = now.plusYears(CERTIFICATE_VALIDITY_YEARS);

        return Certificate.create(
                user,
                serialNumber,
                publicKey,
                encryptedPrivateKey,
                certificateSalt,
                now,
                expiresAt
        );
    }

    private boolean verifyCertificateKeyPair(String simplePassword, Certificate certificate) throws GeneralSecurityException {
        // 개인키 복호화
        PrivateKey privateKey = encryptionUtil.decryptPrivateKey(
                certificate.getPrivateKey(),
                simplePassword,
                certificate.getPrivateKeySalt()
        );

        PublicKey publicKey = encryptionUtil.decodePublicKey(certificate.getPublicKey());

        return encryptionUtil.verifyKeyPair(privateKey, publicKey);
    }

    private User getAndValidateUser(CertificateIssueRequest request) {
        User user = userRepository.findByPhoneNo((request.phoneNo()))
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        if (!user.getName().equals(request.name()) ||
                !user.getBirthDate().equals(request.birthDate())) {
            throw new IllegalArgumentException(INVALID_USER_INFO);
        }
        return user;
    }

    /**
     * 인증서 상태 검증
     */
    private void validateCertificate(Certificate certificate) {
        // 인증서 상태 검증
        if (certificate.getStatus() != CertificateStatus.ACTIVE) {
            throw new IllegalStateException(CERTIFICATE_NOT_ACTIVE + ": " + certificate.getStatus().getState());
        }

        // 만료 검증
        if (certificate.getExpiresAt().isBefore(LocalDateTime.now())) {
            certificate.changeStatus(CertificateStatus.EXPIRED);
            certificateRepository.save(certificate);
            throw new CertificateExpiredException(CERTIFICATE_EXPIRED);
        }
    }

    private void validateSimplePassword(String simplePassword) {
        if (simplePassword == null || simplePassword.length() != 6) {
            throw new InvalidSimplePasswordException(SIMPLE_PASSWORD_LENGTH_INVALID);
        }

        if (!simplePassword.matches("\\d{6}")) {
            throw new InvalidSimplePasswordException(SIMPLE_PASSWORD_FORMAT_INVALID);
        }

        // 연속된 숫자 체크 (오름차순)
        boolean isSequentialAsc = true;
        for (int i = 0; i < 5; i++) {
            if (simplePassword.charAt(i + 1) - simplePassword.charAt(i) != 1) {
                isSequentialAsc = false;
                break;
            }
        }
        if (isSequentialAsc) {
            throw new InvalidSimplePasswordException(SIMPLE_PASSWORD_SEQUENTIAL);
        }

        // 연속된 숫자 체크 (내림차순)
        boolean isSequentialDesc = true;
        for (int i = 0; i < 5; i++) {
            if (simplePassword.charAt(i) - simplePassword.charAt(i + 1) != 1) {
                isSequentialDesc = false;
                break;
            }
        }
        if (isSequentialDesc) {
            throw new InvalidSimplePasswordException(SIMPLE_PASSWORD_SEQUENTIAL);
        }

        // 같은 숫자 반복 체크
        if (simplePassword.chars().distinct().count() == 1) {
            throw new InvalidSimplePasswordException(SIMPLE_PASSWORD_REPEATED);
        }
    }
}
