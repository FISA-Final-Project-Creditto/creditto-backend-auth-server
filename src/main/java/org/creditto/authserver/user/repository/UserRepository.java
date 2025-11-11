package org.creditto.authserver.user.repository;

import org.creditto.authserver.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByPhoneNo(String phoneNo);

    Optional<User> findUserByExternalUserId(String externalUserId);
}
