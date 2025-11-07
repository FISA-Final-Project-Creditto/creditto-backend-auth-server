package org.creditto.authserver.client.repository;

import org.creditto.authserver.client.entity.OAuth2AuthorizationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {

    // State로 Authorization 조회
    Optional<OAuth2AuthorizationEntity> findByState(String state);

    // Authorization Code로 조회
    Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(String authorizationCode);

    // Access Token으로 조회
    Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(String accessToken);

    // Refresh Token으로 조회
    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshToken);

    // OIDC ID Token으로 조회
    Optional<OAuth2AuthorizationEntity> findByOidcIdTokenValue(String idToken);

    // User Code로 조회
    Optional<OAuth2AuthorizationEntity> findByUserCodeValue(String userCode);

    // Device Code로 조회
    Optional<OAuth2AuthorizationEntity> findByDeviceCodeValue(String deviceCode);

    // 복합 조회 - State와 Authorization Code
    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.state = :token " +
            "OR a.authorizationCodeValue = :token " +
            "OR a.accessTokenValue = :token " +
            "OR a.refreshTokenValue = :token " +
            "OR a.oidcIdTokenValue = :token " +
            "OR a.userCodeValue = :token " +
            "OR a.deviceCodeValue = :token")
    Optional<OAuth2AuthorizationEntity> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(
            @Param("token") String token
    );
}
