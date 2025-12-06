package org.creditto.authserver.domain.client.repository;

import lombok.NonNull;
import org.creditto.authserver.domain.client.entity.OAuth2RegisteredClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2RegisteredClientRepository extends JpaRepository<OAuth2RegisteredClient, String> {

    @Query("SELECT c FROM OAuth2RegisteredClient c " +
            "LEFT JOIN FETCH c.clientAuthenticationMethods " +
            "LEFT JOIN FETCH c.authorizationGrantTypes " +
            "LEFT JOIN FETCH c.redirectUris " +
            "LEFT JOIN FETCH c.postLogoutRedirectUris " +
            "LEFT JOIN FETCH c.scopes " +
            "WHERE c.clientId = :clientId")
    Optional<OAuth2RegisteredClient> findByClientId(String clientId);

    @Query("SELECT c FROM OAuth2RegisteredClient c " +
            "LEFT JOIN FETCH c.clientAuthenticationMethods " +
            "LEFT JOIN FETCH c.authorizationGrantTypes " +
            "LEFT JOIN FETCH c.redirectUris " +
            "LEFT JOIN FETCH c.postLogoutRedirectUris " +
            "LEFT JOIN FETCH c.scopes " +
            "WHERE c.id = :clientId")
    @NonNull
    Optional<OAuth2RegisteredClient> findById(@Param("clientId") @NonNull String id);
}
