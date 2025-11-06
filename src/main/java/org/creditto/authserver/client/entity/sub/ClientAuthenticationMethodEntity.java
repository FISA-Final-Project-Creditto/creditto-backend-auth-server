package org.creditto.authserver.client.entity.sub;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.client.entity.OAuth2RegisteredClient;

@Entity
@Table(name = "client_authentication_method")
@Getter
@Builder(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientAuthenticationMethodEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuth2RegisteredClient client;

    @Column(name = "authentication_method", nullable = false)
    private String authenticationMethod;

    public static ClientAuthenticationMethodEntity of(String authenticationMethod) {
        return ClientAuthenticationMethodEntity.builder()
                .authenticationMethod(authenticationMethod)
                .build();
    }

    public void updateClient(OAuth2RegisteredClient client) {
        this.client = client;
    }
}
