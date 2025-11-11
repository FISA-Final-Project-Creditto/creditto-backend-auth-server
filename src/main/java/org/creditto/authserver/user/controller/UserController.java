package org.creditto.authserver.user.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.global.response.ApiResponseUtil;
import org.creditto.authserver.global.response.BaseResponse;
import org.creditto.authserver.global.response.SuccessCode;
import org.creditto.authserver.user.dto.UserRegisterRequest;
import org.creditto.authserver.user.dto.UserResponse;
import org.creditto.authserver.user.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * 사용자 등록
     */
    @PostMapping("/register")
    public ResponseEntity<BaseResponse<UserResponse>> registerUser(@Valid @RequestBody UserRegisterRequest request) {
        log.info("사용자 등록 요청 - 이름: {}, 전화번호: {}", request.name(), request.phoneNo());
        return ApiResponseUtil.success(SuccessCode.OK, userService.registerUser(request));
    }

    /**
     * 사용자 조회 (ID)
     */
    @GetMapping("/{externalUserId}")
    public ResponseEntity<BaseResponse<UserResponse>> getUser(@PathVariable String externalUserId) {
        log.info("사용자 조회 요청 - ID: {}", externalUserId);
        return ApiResponseUtil.success(SuccessCode.OK, userService.getUser(externalUserId));
    }

    /**
     * 사용자 조회 (전화번호)
     */
    @GetMapping("/phone/{phoneNo}")
    public ResponseEntity<BaseResponse<UserResponse>> getUserByPhoneNo(@PathVariable String phoneNo) {
        log.info("사용자 조회 요청 - 전화번호: {}", phoneNo);
        return ApiResponseUtil.success(SuccessCode.OK, userService.getUserByPhoneNo(phoneNo));
    }

    /**
     * 전체 사용자 조회
     */
    @GetMapping
    public ResponseEntity<BaseResponse<List<UserResponse>>> getAllUsers() {
        log.info("전체 사용자 조회 요청");
        return ApiResponseUtil.success(SuccessCode.OK, userService.getAllUsers());
    }
}