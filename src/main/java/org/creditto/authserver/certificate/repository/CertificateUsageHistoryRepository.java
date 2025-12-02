package org.creditto.authserver.certificate.repository;

import org.creditto.authserver.certificate.entity.CertificateUsageHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertificateUsageHistoryRepository extends JpaRepository<CertificateUsageHistory, Long> {
}