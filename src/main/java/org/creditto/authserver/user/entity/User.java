package org.creditto.authserver.user.entity;

import jakarta.persistence.*;
import lombok.*;
import org.creditto.authserver.user.dto.UserRegisterRequest;
import org.creditto.authserver.user.enums.UserRoles;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Entity
@Getter
@Table(name = "users")
@Builder(access = AccessLevel.PRIVATE)
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, name = "birth_date")
    private LocalDate birthDate;

    @Column(nullable = false, name = "phone_no")
    private String phoneNo;

    @Column(nullable = false, name = "address")
    private String address;

    @Column(nullable = false, name = "country_code")
    private String countryCode;

    @Column(unique = true)
    private String externalUserId;

    private LocalDate expiredAt;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<UserRoles> roles;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PostPersist
    protected void onCreate() {
        if (this.externalUserId == null) {
            this.externalUserId = UUID.randomUUID().toString();
        }
    }

    public static User create (UserRegisterRequest request) {
        return User.builder()
                .name(request.name())
                .address(request.address())
                .countryCode(request.countryCode())
                .roles(Set.of(UserRoles.CUSTOMER))
                .birthDate(request.birthDate())
                .phoneNo(request.phoneNo())
                .build();
    }

    public List<String> mapUserRolesToList() {
        return this.getRoles().stream()
                .map(UserRoles::name)
                .toList();
    }
}
