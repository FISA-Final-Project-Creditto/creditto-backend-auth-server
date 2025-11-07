package org.creditto.authserver.user.dto;

import lombok.Builder;
import org.creditto.authserver.user.entity.User;

import java.time.LocalDate;

@Builder
public record UserResponse(
        Long id,
        String name,
        LocalDate birthDate,
        String phoneNo,
        String address
) {
    public static UserResponse from(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .name(user.getName())
                .birthDate(user.getBirthDate())
                .phoneNo(user.getPhoneNo())
                .address(user.getAddress())
                .build();
    }
}