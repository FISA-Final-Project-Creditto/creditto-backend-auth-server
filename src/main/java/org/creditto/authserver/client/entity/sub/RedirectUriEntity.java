package org.creditto.authserver.client.entity.sub;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.client.entity.OAuth2RegisteredClient;

@Entity
@Table(name = "redirect_uri")
@Getter
@Builder(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class RedirectUriEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2RegisteredClient client;

    @Column(name = "redirect_uri", nullable = false, length = 1000)
    private String redirectUri;

    public static RedirectUriEntity of(String redirectUri) {
        return RedirectUriEntity.builder()
                .redirectUri(redirectUri)
                .build();
    }
}