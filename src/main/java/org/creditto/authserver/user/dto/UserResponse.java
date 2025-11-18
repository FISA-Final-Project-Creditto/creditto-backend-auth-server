package org.creditto.authserver.user.dto;

import lombok.Builder;
import org.creditto.authserver.user.entity.User;

import java.time.LocalDate;

@Builder
public record UserResponse(
        String externalUserId,
        String name,
        LocalDate birthDate,
        String countryCode,
        String phoneNo,
        String address
) {
    public static UserResponse from(User user) {
        return UserResponse.builder()
                .externalUserId(user.getExternalUserId())
                .name(user.getName())
                .birthDate(user.getBirthDate())
                .countryCode(user.getCountryCode())
                .phoneNo(user.getPhoneNo())
                .address(user.getAddress())
                .build();
    }
}