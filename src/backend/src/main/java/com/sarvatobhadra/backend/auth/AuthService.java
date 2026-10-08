package com.sarvatobhadra.backend.auth;

import com.sarvatobhadra.backend.auth.dto.LoginRequest;
import com.sarvatobhadra.backend.auth.dto.LoginResponse;
import com.sarvatobhadra.backend.auth.dto.RegisterRequest;
import com.sarvatobhadra.backend.common.enums.UserRole;
import com.sarvatobhadra.backend.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;

/**
 * Service encapsulating authentication and user registration logic.
 * Handles credential verification via {@link AuthenticationManager} and JWT token issuance via {@link JwtService}.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Authenticates existing user credentials and returns JWT access token.
     */
    public LoginResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        UserEntity userEntity = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserDetails userDetails = new User(
                userEntity.getUsername(),
                userEntity.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority(userEntity.getRole().name()))
        );

        String token = jwtService.generateToken(userDetails);

        return LoginResponse.builder()
                .token(token)
                .username(userEntity.getUsername())
                .email(userEntity.getEmail())
                .role(userEntity.getRole())
                .expiresInMs(86400000) // 24 Hours
                .build();
    }

    /**
     * Registers a new user account with BCrypt encrypted password.
     */
    @Transactional
    public LoginResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username '" + request.getUsername() + "' is already taken");
        }

        UserRole role = request.getRole() != null ? request.getRole() : UserRole.ROLE_ANALYST;

        UserEntity newUser = UserEntity.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(role)
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .build();

        userRepository.save(newUser);

        LoginRequest loginRequest = new LoginRequest(request.getUsername(), request.getPassword());
        return login(loginRequest);
    }
}
