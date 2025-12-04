package org.creditto.authserver.domain.certificate.repository;

import org.creditto.authserver.domain.certificate.enums.CertificateStatus;
import org.creditto.authserver.domain.certificate.entity.Certificate;
import org.creditto.authserver.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    @Query("SELECT ctf FROM Certificate ctf JOIN FETCH ctf.user WHERE ctf.serialNumber = :serial")
    Optional<Certificate> findBySerialNumber(@Param("serial") String serialNumber);

    Optional<Certificate> findByUserAndStatus(User user, CertificateStatus status);

    boolean existsCertificateByStatusAndUser(CertificateStatus status, User user);
}
