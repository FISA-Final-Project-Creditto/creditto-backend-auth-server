package org.creditto.authserver.domain.certificate.entity;

import jakarta.persistence.*;
import lombok.*;

import org.creditto.authserver.domain.certificate.enums.CertificateStatus;
import org.creditto.authserver.domain.user.entity.User;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "certificates")
@Getter
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(access = AccessLevel.PRIVATE)
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true)
    private String serialNumber;

    /**
     * 전자서명을 위한 인증서 공개키
     */
    @Column(nullable = false, length = 2048)
    private String publicKey;

    /**
     * 인증서 개인키 (Encrypt By AES256)
     * 로그인 시 간편비밀번호로 복호화하여 검증
     */
    @Column(nullable = false, length = 4096)
    private String privateKey;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateStatus status;

    @CreatedDate
    @Column(name = "issued_at", nullable = false, updatable = false)
    private LocalDateTime issuedAt;

    private LocalDateTime expiresAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(length = 100)
    private String privateKeySalt;

    private String revokeReason;

    public static Certificate create(
            User user,
            String serialNumber,
            String publicKey,
            String encryptedPrivateKey,
            String privateKeySalt,
            LocalDateTime issuedAt,
            LocalDateTime expiresAt) {
        return Certificate.builder()
                .user(user)
                .serialNumber(serialNumber)
                .publicKey(publicKey)
                .privateKey(encryptedPrivateKey)
                .privateKeySalt(privateKeySalt)
                .status(CertificateStatus.ACTIVE)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .build();
    }

    /**
     * 인증서 상태 변경
     */
    public void changeStatus(CertificateStatus status) {
        this.status = status;
    }

    /**
     * 인증서 폐기
     */
    public void revoke(String reason) {
        this.status = CertificateStatus.REVOKE;
        this.revokeReason = reason;
    }
}
