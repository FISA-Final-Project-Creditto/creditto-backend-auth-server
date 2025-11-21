package org.creditto.authserver.certificate.repository;

import org.creditto.authserver.certificate.enums.CertificateStatus;
import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    @Query("SELECT ctf FROM Certificate ctf JOIN FETCH ctf.user WHERE ctf.serialNumber = :serial")
    Optional<Certificate> findBySerialNumber(@Param("serial") String serialNumber);

    List<Certificate> findByUser(User user);

    Optional<Certificate> findByUserAndStatus(User user, CertificateStatus status);

    long countByUserAndStatus(User user, CertificateStatus status);

    boolean existsCertificateByStatusAndUser(CertificateStatus status, User user);
}
