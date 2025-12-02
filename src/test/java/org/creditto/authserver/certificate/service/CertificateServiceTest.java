package org.creditto.authserver.certificate.service;

import org.creditto.authserver.auth.utils.CertificateEncryptionUtil;
import org.creditto.authserver.certificate.dto.CertificateIssueRequest;
import org.creditto.authserver.certificate.dto.CertificateSerialRequest;
import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.certificate.entity.CertificateUsageHistory;
import org.creditto.authserver.certificate.enums.CertificateStatus;
import org.creditto.authserver.certificate.repository.CertificateRepository;
import org.creditto.authserver.certificate.repository.CertificateUsageHistoryRepository;
import org.creditto.authserver.global.exception.InvalidSimplePasswordException;
import org.creditto.authserver.user.entity.User;
import org.creditto.authserver.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.creditto.authserver.auth.constants.ParameterConstants.CERTIFICATE_SERIAL;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertificateServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private CertificateRepository certificateRepository;
    @Mock
    private CertificateUsageHistoryRepository certificateUsageHistoryRepository;
    @Mock
    private CertificateEncryptionUtil encryptionUtil;

    @InjectMocks
    private CertificateService certificateService;

    private CertificateIssueRequest certificateIssueRequest;
    private CertificateSerialRequest certificateSerialRequest;
    private User registerUser;
    private User authUser;
    private User invalidAuthUser;
    private User serialLookupUser;

    @BeforeEach
    void setUp() {
        certificateIssueRequest = new CertificateIssueRequest(
                1L,
                "홍길동",
                "010-1111-2222",
                LocalDate.of(1990, 1, 1),
                "938475"
        );

        certificateSerialRequest = new CertificateSerialRequest("홍길동", "010-7777-8888");

        registerUser = User.create(new org.creditto.authserver.user.dto.UserRegisterRequest(
                "홍길동",
                LocalDate.of(1990, 1, 1),
                "KR",
                "010-1111-2222",
                "서울시 종로구"
        ));
        ReflectionTestUtils.setField(registerUser, "id", 1L);

        authUser = User.create(new org.creditto.authserver.user.dto.UserRegisterRequest(
                "홍길동",
                LocalDate.of(1990, 1, 1),
                "KR",
                "010-2222-3333",
                "서울시 종로구"
        ));
        ReflectionTestUtils.setField(authUser, "id", 2L);

        invalidAuthUser = User.create(new org.creditto.authserver.user.dto.UserRegisterRequest(
                "홍길동",
                LocalDate.of(1990, 1, 1),
                "KR",
                "010-4444-5555",
                "서울시 종로구"
        ));
        ReflectionTestUtils.setField(invalidAuthUser, "id", 3L);

        serialLookupUser = User.create(new org.creditto.authserver.user.dto.UserRegisterRequest(
                "홍길동",
                LocalDate.of(1990, 1, 1),
                "KR",
                "010-7777-8888",
                "서울시 종로구"
        ));
        ReflectionTestUtils.setField(serialLookupUser, "id", 4L);
    }

    @Test
    @DisplayName("인증서 발급 요청 시 RSA 키 생성과 사용 이력이 저장된다")
    void issueCertificate_createsCertificate() throws Exception {
        // given
        when(userRepository.findById(certificateIssueRequest.userId())).thenReturn(Optional.of(registerUser));
        when(certificateRepository.existsCertificateByStatusAndUser(CertificateStatus.ACTIVE, registerUser)).thenReturn(false);

        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        when(encryptionUtil.generateRSAKeyPair()).thenReturn(keyPair);
        when(encryptionUtil.encryptPrivateKey(eq(keyPair.getPrivate()), eq(certificateIssueRequest.simplePassword()), anyString()))
                .thenReturn("encrypted-private-key");
        when(encryptionUtil.encodePublicKey(keyPair.getPublic())).thenReturn("encoded-public-key");
        when(certificateRepository.save(any(Certificate.class))).thenAnswer(invocation -> invocation.getArgument(0));

        // when
        var response = certificateService.issueCertificate(certificateIssueRequest, "127.0.0.1", "JUnit");

        // then
        ArgumentCaptor<Certificate> captor = ArgumentCaptor.forClass(Certificate.class);
        verify(certificateRepository).save(captor.capture());
        Certificate saved = captor.getValue();
        assertThat(saved.getUser()).isEqualTo(registerUser);
        assertThat(saved.getPublicKey()).isEqualTo("encoded-public-key");
        assertThat(response.serialNumber()).isEqualTo(saved.getSerialNumber());
        verify(certificateUsageHistoryRepository).save(any(CertificateUsageHistory.class));
    }

    @Test
    @DisplayName("올바른 간편비밀번호로 인증 시 인증서가 반환된다")
    void authenticateWithCertificate_success() throws Exception {
        // given
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Certificate certificate = Certificate.create(
                authUser,
                "serial-123",
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                "encrypted-key",
                "salt",
                LocalDateTime.of(2024, 1, 1, 12, 0),
                LocalDateTime.of(2099, 1, 1, 12, 0).plusYears(1)
        );

        when(certificateRepository.findBySerialNumber("serial-123")).thenReturn(Optional.of(certificate));
        when(encryptionUtil.decryptPrivateKey("encrypted-key", "123456", "salt")).thenReturn(keyPair.getPrivate());
        when(encryptionUtil.decodePublicKey(anyString())).thenReturn(keyPair.getPublic());
        when(encryptionUtil.verifyKeyPair(any(PrivateKey.class), any(PublicKey.class))).thenReturn(true);

        // when
        Certificate authenticated = certificateService.authenticateWithCertificate("serial-123", "123456", "127.0.0.1", "JUnit");

        // then
        assertThat(authenticated.getSerialNumber()).isEqualTo("serial-123");
        verify(certificateUsageHistoryRepository).save(any(CertificateUsageHistory.class));
    }

    @Test
    @DisplayName("간편비밀번호가 일치하지 않으면 인증 실패 예외를 던진다")
    void authenticateWithCertificate_invalidPassword() throws Exception {
        // given
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Certificate certificate = Certificate.create(
                invalidAuthUser,
                "serial-999",
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                "encrypted-key",
                "salt",
                LocalDateTime.now(),
                LocalDateTime.now().plusYears(1)
        );

        when(certificateRepository.findBySerialNumber("serial-999")).thenReturn(Optional.of(certificate));
        when(encryptionUtil.decryptPrivateKey(anyString(), anyString(), anyString())).thenReturn(keyPair.getPrivate());
        when(encryptionUtil.decodePublicKey(anyString())).thenReturn(keyPair.getPublic());
        when(encryptionUtil.verifyKeyPair(any(PrivateKey.class), any(PublicKey.class))).thenReturn(false);

        // when & then
        assertThatThrownBy(() -> certificateService.authenticateWithCertificate("serial-999", "123456", "127.0.0.1", "JUnit"))
                .isInstanceOf(InvalidSimplePasswordException.class);
        verify(certificateUsageHistoryRepository).save(any(CertificateUsageHistory.class));
    }

    @Test
    @DisplayName("사용자 정보를 기반으로 활성 인증서 일련번호를 조회한다")
    void getSerialNumberByUser_returnsActiveSerial() {
        // given
        Certificate certificate = Certificate.create(
                serialLookupUser,
                "serial-0001",
                "public-key",
                "private-key",
                "salt",
                LocalDateTime.now(),
                LocalDateTime.now().plusYears(1)
        );

        when(userRepository.findByNameAndPhoneNo(certificateSerialRequest.username(), certificateSerialRequest.phoneNo())).thenReturn(Optional.of(serialLookupUser));
        when(certificateRepository.findByUserAndStatus(serialLookupUser, CertificateStatus.ACTIVE)).thenReturn(Optional.of(certificate));

        // when
        Map<String, String> response = certificateService.getSerialNumberByUser(certificateSerialRequest);

        // then
        assertThat(response).containsEntry(CERTIFICATE_SERIAL, "serial-0001");
    }

}
