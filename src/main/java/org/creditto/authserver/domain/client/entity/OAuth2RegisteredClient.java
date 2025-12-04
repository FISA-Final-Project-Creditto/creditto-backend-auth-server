package org.creditto.authserver.domain.client.entity;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.client.entity.sub.*;
import org.creditto.authserver.domain.client.entity.sub.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "oauth2_registered_client")
@Getter
@EntityListeners(AuditingEntityListener.class)
@Builder(access = AccessLevel.PROTECTED)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2RegisteredClient {

    @Id
    private String id;

    // 클라이언트 식별자 (서버명)
    @Column(name = "client_id")
    private String clientId;

    @Column(name = "client_id_issued_at")
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    private String clientName;

    /**
     * 클라이언트 인증방법
     * Reference : org.springframework.security.oauth2.core.ClientAuthenticationMethod
     */
    @OneToMany(
            mappedBy = "client",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.EAGER
    )
    @Builder.Default
    private Set<ClientAuthenticationMethodEntity> clientAuthenticationMethods = new HashSet<>();

    /**
     * 인가 GrantType 목록
     * Reference : org.springframework.security.oauth2.core.AuthorizationGrantType
     */
    @OneToMany(
            mappedBy = "client",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.EAGER
    )
    @Builder.Default
    private Set<AuthorizationGrantTypeEntity> authorizationGrantTypes = new HashSet<>();

    /**
     * 리다이렉트 URI 목록
     *
     * @OneToMany 관계로 별도 테이블에 저장
     * Authorization Code Flow에서 사용
     */
    @OneToMany(
            mappedBy = "client",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.EAGER
    )
    @Builder.Default
    private Set<RedirectUriEntity> redirectUris = new HashSet<>();

    /**
     * Post Logout 리다이렉트 URI 목록
     */
    @OneToMany(
            mappedBy = "client",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.EAGER
    )
    @Builder.Default
    private Set<PostLogoutRedirectUriEntity> postLogoutRedirectUris = new HashSet<>();

    /**
     * 스코프 목록
     */
    @OneToMany(
            mappedBy = "client",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.EAGER
    )
    @Builder.Default
    private Set<ClientScope> scopes = new HashSet<>();

    /**
     * 클라이언트 설정 (JSON 형식)
     */
    @Column(name = "client_settings", length = 2000)
    private String clientSettings;

    /**
     * 토큰 설정 (JSON 형식)
     * TokenSettings 객체를 JSON으로 직렬화하여 저장
     */
    @Column(name = "token_settings", length = 2000)
    private String tokenSettings;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (clientIdIssuedAt == null) {
            clientIdIssuedAt = Instant.now();
        }
    }

    public void addClientAuthenticationMethod(ClientAuthenticationMethodEntity method) {
        this.clientAuthenticationMethods.add(method);
        method.updateClient(this);
    }

    public void addAuthorizationGrantType(AuthorizationGrantTypeEntity grantType) {
        this.authorizationGrantTypes.add(grantType);
        grantType.updateClient(this);
    }

    public void addRedirectUri(RedirectUriEntity redirectUri) {
        this.redirectUris.add(redirectUri);
        redirectUri.updateClient(this);
    }

    public void addPostLogoutRedirectUri(PostLogoutRedirectUriEntity uri) {
        this.postLogoutRedirectUris.add(uri);
        uri.updateClient(this);
    }

    public void addScope(ClientScope scope) {
        this.scopes.add(scope);
        scope.updateClient(this);
    }
}
