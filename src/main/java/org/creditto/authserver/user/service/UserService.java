package org.creditto.authserver.user.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.user.dto.UserRegisterRequest;
import org.creditto.authserver.user.dto.UserResponse;
import org.creditto.authserver.user.entity.User;
import org.creditto.authserver.user.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.creditto.authserver.global.response.error.ErrorMessage.*;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository userRepository;

    /**
     * 사용자 등록
     */
    @Transactional
    public UserResponse registerUser(UserRegisterRequest request) {
        // 중복 전화번호 검증
        if (userRepository.findByPhoneNo(request.phoneNo()).isPresent()) {
            throw new IllegalArgumentException(DUPLICATED_REQUEST + ": " + request.phoneNo());
        }

        // User 엔티티 생성
        User user = User.create(request);
        User savedUser = userRepository.save(user);

        log.info("사용자 등록 완료 - 이름: {}, 전화번호: {}", savedUser.getName(), savedUser.getPhoneNo());

        return UserResponse.from(savedUser);
    }

    /**
     * 사용자 조회 (ID)
     */
    public UserResponse getUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        return UserResponse.from(user);
    }

    /**
     * 사용자 조회 (전화번호)
     */
    public UserResponse getUserByPhoneNo(String phoneNo) {
        User user = userRepository.findByPhoneNo(phoneNo)
                .orElseThrow(() -> new EntityNotFoundException(USER_NOT_FOUND));

        return UserResponse.from(user);
    }

    /**
     * 전체 사용자 조회
     */
    public List<UserResponse> getAllUsers() {
        return userRepository.findAll().stream()
                .map(UserResponse::from)
                .toList();
    }
}