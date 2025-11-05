package org.creditto.authserver.certificate.repository;

import org.creditto.authserver.certificate.entity.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    @Query("SELECT ctf FROM Certificate ctf JOIN FETCH ctf.user WHERE ctf.serialNumber = :serial")
    Optional<Certificate> findBySerialNumber(@Param("serial") String serialNumber);
}
