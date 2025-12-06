package org.creditto.authserver.domain.client.entity.sub;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.domain.client.entity.OAuth2RegisteredClient;

@Entity
@Table(name = "authorization_grant_type")
@Getter
@Builder(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthorizationGrantTypeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2RegisteredClient client;

    @Column(name = "grant_type", nullable = false, length = 100)
    private String grantType;

    public static AuthorizationGrantTypeEntity of(String grantType) {
        return AuthorizationGrantTypeEntity.builder()
                .grantType(grantType)
                .build();
    }

    public void updateClient(OAuth2RegisteredClient client) {
        this.client = client;
    }
}
