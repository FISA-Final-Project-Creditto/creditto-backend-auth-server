package org.creditto.authserver.client.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.time.LocalDateTime;

/**
 * OAuth2 Authorization 정보를 저장하는 엔티티
 * 발급된 토큰과 관련 메타데이터, 민감한 사용자 정보를 저장
 */
@Entity
@Table(name = "oauth2_authorization")
@Getter
@EntityListeners(AuditingEntityListener.class)
@Builder(access = AccessLevel.PUBLIC)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2AuthorizationEntity {

    @Id
    @Column(length = 100)
    private String id;

    // OAuth2RegisteredClient의 ID 참조
    @Column(name = "registered_client_id", length = 100, nullable = false)
    private String registeredClientId;

    // 주체 식별자 (사용자 ID)
    @Column(name = "principal_name", length = 200, nullable = false)
    private String principalName;

    // Grant Type (예: certificate, authorization_code 등)
    @Column(name = "authorization_grant_type", length = 100, nullable = false)
    private String authorizationGrantType;

    // 승인된 스코프 (공백으로 구분)
    @Column(name = "authorized_scopes", length = 1000)
    private String authorizedScopes;

    // 속성 정보 (JSON 형식으로 저장 - 민감한 정보 포함)
    @Column(name = "attributes", columnDefinition = "TEXT")
    private String attributes;

    // 상태 정보
    @Column(length = 500)
    private String state;

    // Authorization Code 관련
    @Column(name = "authorization_code_value", columnDefinition = "TEXT")
    private String authorizationCodeValue;

    @Column(name = "authorization_code_issued_at")
    private Instant authorizationCodeIssuedAt;

    @Column(name = "authorization_code_expires_at")
    private Instant authorizationCodeExpiresAt;

    @Column(name = "authorization_code_metadata", columnDefinition = "TEXT")
    private String authorizationCodeMetadata;

    // Access Token 관련
    @Column(name = "access_token_value", columnDefinition = "TEXT")
    private String accessTokenValue;

    @Column(name = "access_token_issued_at")
    private Instant accessTokenIssuedAt;

    @Column(name = "access_token_expires_at")
    private Instant accessTokenExpiresAt;

    @Column(name = "access_token_metadata", columnDefinition = "TEXT")
    private String accessTokenMetadata;

    @Column(name = "access_token_type", length = 100)
    private String accessTokenType;

    @Column(name = "access_token_scopes", length = 1000)
    private String accessTokenScopes;

    // Refresh Token 관련
    @Column(name = "refresh_token_value", columnDefinition = "TEXT")
    private String refreshTokenValue;

    @Column(name = "refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;

    @Column(name = "refresh_token_expires_at")
    private Instant refreshTokenExpiresAt;

    @Column(name = "refresh_token_metadata", columnDefinition = "TEXT")
    private String refreshTokenMetadata;

    // OIDC ID Token 관련
    @Column(name = "oidc_id_token_value", columnDefinition = "TEXT")
    private String oidcIdTokenValue;

    @Column(name = "oidc_id_token_issued_at")
    private Instant oidcIdTokenIssuedAt;

    @Column(name = "oidc_id_token_expires_at")
    private Instant oidcIdTokenExpiresAt;

    @Column(name = "oidc_id_token_metadata", columnDefinition = "TEXT")
    private String oidcIdTokenMetadata;

    @Column(name = "oidc_id_token_claims", columnDefinition = "TEXT")
    private String oidcIdTokenClaims;

    // User Code 관련 (Device Authorization Grant)
    @Column(name = "user_code_value", columnDefinition = "TEXT")
    private String userCodeValue;

    @Column(name = "user_code_issued_at")
    private Instant userCodeIssuedAt;

    @Column(name = "user_code_expires_at")
    private Instant userCodeExpiresAt;

    @Column(name = "user_code_metadata", columnDefinition = "TEXT")
    private String userCodeMetadata;

    // Device Code 관련
    @Column(name = "device_code_value", columnDefinition = "TEXT")
    private String deviceCodeValue;

    @Column(name = "device_code_issued_at")
    private Instant deviceCodeIssuedAt;

    @Column(name = "device_code_expires_at")
    private Instant deviceCodeExpiresAt;

    @Column(name = "device_code_metadata", columnDefinition = "TEXT")
    private String deviceCodeMetadata;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    // Builder를 통한 생성
    public static OAuth2AuthorizationEntity create(
            String id,
            String registeredClientId,
            String principalName,
            String authorizationGrantType) {
        return OAuth2AuthorizationEntity.builder()
                .id(id)
                .registeredClientId(registeredClientId)
                .principalName(principalName)
                .authorizationGrantType(authorizationGrantType)
                .build();
    }
}
