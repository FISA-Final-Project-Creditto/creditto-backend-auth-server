package org.creditto.authserver.domain.client.entity.sub;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.domain.client.entity.OAuth2RegisteredClient;

@Entity
@Table(name = "client_scope")
@Getter
@Builder(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientScope {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2RegisteredClient client;

    @Column(name = "scope", nullable = false, length = 100)
    private String scope;

    public static ClientScope of(String scope) {
        return ClientScope.builder()
                .scope(scope)
                .build();
    }

    public void updateClient(OAuth2RegisteredClient client) {
        this.client = client;
    }
}