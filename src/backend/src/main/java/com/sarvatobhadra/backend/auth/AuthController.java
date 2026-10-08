package com.sarvatobhadra.backend.auth;

import com.sarvatobhadra.backend.auth.dto.LoginRequest;
import com.sarvatobhadra.backend.auth.dto.LoginResponse;
import com.sarvatobhadra.backend.auth.dto.RegisterRequest;
import com.sarvatobhadra.backend.common.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Controller exposing public authentication endpoints for user login, account registration,
 * and current session validation.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Authenticates user credentials and returns JWT bearer token.
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success(response, "User authenticated successfully"));
    }

    /**
     * Registers a new user account (Analyst / Admin role).
     * POST /api/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<LoginResponse>> register(@Valid @RequestBody RegisterRequest request) {
        LoginResponse response = authService.register(request);
        return ResponseEntity.ok(ApiResponse.success(response, "User account registered successfully"));
    }
}
