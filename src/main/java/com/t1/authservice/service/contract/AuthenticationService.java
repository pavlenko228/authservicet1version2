package com.t1.authservice.service.contract;

import com.t1.authservice.domain.dto.AuthenticationResponse;
import com.t1.authservice.domain.dto.LoginRequest;
import com.t1.authservice.domain.dto.RegistrationRequest;
import com.t1.authservice.domain.model.User;
import com.t1.authservice.exception.MissingAuthorizationHeaderException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {

    AuthenticationResponse register(RegistrationRequest registrationRequest, HttpServletResponse response);

    AuthenticationResponse authenticate(LoginRequest loginRequest, HttpServletResponse response);

    AuthenticationResponse refreshToken(HttpServletRequest request, HttpServletResponse response) throws MissingAuthorizationHeaderException;

    void revokeAllToken(User user);

    void revokeAllTokenController(String email);

    void saveUserToken(String accessToken, String refreshToken, User user);
}