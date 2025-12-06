package org.creditto.authserver.domain.certificate.entity;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.domain.certificate.enums.HistoryAction;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "certificate_usage_history")
@Getter
@Builder
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class CertificateUsageHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_id", nullable = false)
    private Certificate certificate;

    @Column(nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private HistoryAction action;

    @Column(nullable = false)
    private boolean success;

    @Column(name = "ip_address", length = 50)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "failure_reason", length = 500)
    private String failureReason;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    public static CertificateUsageHistory create(Certificate certificate, HistoryAction action, boolean success, String ipAddress, String userAgent, String failureReason) {
        return CertificateUsageHistory.builder()
                .certificate(certificate)
                .action(action)
                .success(success)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .failureReason(failureReason)
                .build();
    }
}