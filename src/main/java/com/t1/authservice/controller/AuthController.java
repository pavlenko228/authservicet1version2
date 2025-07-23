package com.t1.authservice.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.t1.authservice.domain.dto.AuthenticationResponse;
import com.t1.authservice.domain.dto.LoginRequest;
import com.t1.authservice.domain.dto.RegistrationRequest;
import com.t1.authservice.service.contract.AuthenticationService;


@RestController
@RequestMapping("api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication controllers")
public class AuthController {
    private final AuthenticationService authenticationService;

    @Operation(summary = "Registration user")
    @PostMapping("/registration")
    public ResponseEntity<?> register(@RequestBody RegistrationRequest registrationRequest, HttpServletResponse response) {
        AuthenticationResponse authenticationResponse = authenticationService.register(registrationRequest, response);

        return ResponseEntity.ok(authenticationResponse);
    }

    @Operation(summary = "Authentication user")
    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        AuthenticationResponse authenticationResponse = authenticationService.authenticate(loginRequest, response);

        return ResponseEntity.ok(authenticationResponse);
    }

    @Operation(summary = "Refresh tokens")
    @PostMapping("/refresh_token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        AuthenticationResponse authenticationResponse = authenticationService.refreshToken(request, response);

        return ResponseEntity.ok(authenticationResponse);
    }

    @Operation(summary = "Revoke tokens")
    @PostMapping("/revoke_token")
    public ResponseEntity<?> revokeAllToken(String email) {
        authenticationService.revokeAllTokenController(email);

        return ResponseEntity.ok("Revoke was succesfull");
    }
    
}

