package org.creditto.authserver.domain.user.repository;

import org.creditto.authserver.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByPhoneNo(String phoneNo);

    Optional<User> findByNameAndPhoneNo(String name, String phoneNo);
}
