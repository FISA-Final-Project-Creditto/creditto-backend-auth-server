package org.creditto.authserver.certificate.repository;

import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.certificate.entity.CertificateUsageHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface CertificateUsageHistoryRepository extends JpaRepository<CertificateUsageHistory, Long> {

    List<CertificateUsageHistory> findByCertificateIdOrderByCreatedAtDesc(Long certificateId);

    List<CertificateUsageHistory> findByCertificateIdAndSuccessFalseAndCreatedAtAfter(
            Long certificateId,
            LocalDateTime after
    );

    List<CertificateUsageHistory> findByCertificate_User_IdOrderByCreatedAtDesc(Long userId);

    List<CertificateUsageHistory> findByCertificate(Certificate certificate);
}