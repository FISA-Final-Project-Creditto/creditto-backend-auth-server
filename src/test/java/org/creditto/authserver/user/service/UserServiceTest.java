package org.creditto.authserver.user.service;

import org.creditto.authserver.user.dto.UserRegisterRequest;
import org.creditto.authserver.user.dto.UserResponse;
import org.creditto.authserver.user.entity.User;
import org.creditto.authserver.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import jakarta.persistence.EntityNotFoundException;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    private UserRegisterRequest baseRequest;
    private UserRegisterRequest duplicateRequest;
    private UserRegisterRequest secondRequest;

    @BeforeEach
    void setUp() {
        baseRequest = new UserRegisterRequest(
                "홍길동",
                LocalDate.of(1990, 1, 1),
                "KR",
                "010-1111-2222",
                "서울시 종로구"
        );

        duplicateRequest = new UserRegisterRequest(
                "홍길동",
                LocalDate.of(1990, 1, 1),
                "KR",
                "010-3333-4444",
                "서울시 종로구"
        );

        secondRequest = new UserRegisterRequest(
                "홍길동",
                LocalDate.of(1990, 1, 1),
                "KR",
                "010-2222-3333",
                "서울시 종로구"
        );
    }

    @Test
    @DisplayName("사용자 등록 시 신규 사용자 정보를 저장한다")
    void registerUser_savesNewUser() {
        // given
        User savedUser = User.create(baseRequest);
        ReflectionTestUtils.setField(savedUser, "id", 1L);

        when(userRepository.findByPhoneNo(baseRequest.phoneNo())).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        // when
        UserResponse response = userService.registerUser(baseRequest);

        // then
        assertThat(response.userId()).isEqualTo(1L);
        assertThat(response.name()).isEqualTo(baseRequest.name());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("중복 전화번호로 사용자 등록 시 예외가 발생한다")
    void registerUser_duplicatePhoneThrowsException() {
        // given
        when(userRepository.findByPhoneNo(duplicateRequest.phoneNo())).thenReturn(Optional.of(User.create(duplicateRequest)));

        // when & then
        assertThatThrownBy(() -> userService.registerUser(duplicateRequest))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("ID로 사용자 조회 시 존재하지 않으면 예외를 던진다")
    void getUser_notFoundThrowsException() {
        // given
        when(userRepository.findById(1L)).thenReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> userService.getUser(1L))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    @DisplayName("전체 사용자 조회 시 응답 DTO 목록을 반환한다")
    void getAllUsers_returnsResponses() {
        // given
        User first = User.create(baseRequest);
        User second = User.create(secondRequest);
        ReflectionTestUtils.setField(first, "id", 10L);
        ReflectionTestUtils.setField(second, "id", 11L);
        when(userRepository.findAll()).thenReturn(List.of(first, second));

        // when
        List<UserResponse> responses = userService.getAllUsers();

        // then
        assertThat(responses).hasSize(2);
        assertThat(responses.get(0).userId()).isEqualTo(10L);
        assertThat(responses.get(1).phoneNo()).isEqualTo("010-2222-3333");
    }
}
