package com.sarvatobhadra.backend.auth.dto;

import com.sarvatobhadra.backend.common.enums.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data Transfer Object for authentication response containing JWT token and user metadata.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private String token;
    private String username;
    private String email;
    private UserRole role;
    private long expiresInMs;
}
