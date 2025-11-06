package org.creditto.authserver.client.entity.sub;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.client.entity.OAuth2RegisteredClient;

@Entity
@Table(name = "post_logout_redirect_uri")
@Getter
@Builder(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class PostLogoutRedirectUriEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2RegisteredClient client;

    @Column(name = "post_logout_redirect_uri", nullable = false, length = 1000)
    private String postLogoutRedirectUri;

    public static PostLogoutRedirectUriEntity of(String postLogoutRedirectUri) {
        return PostLogoutRedirectUriEntity.builder()
                .postLogoutRedirectUri(postLogoutRedirectUri)
                .build();
    }
}