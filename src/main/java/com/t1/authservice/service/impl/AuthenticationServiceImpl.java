package com.t1.authservice.service.impl;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.t1.authservice.domain.dto.AuthenticationResponse;
import com.t1.authservice.domain.dto.LoginRequest;
import com.t1.authservice.domain.dto.RegistrationRequest;
import com.t1.authservice.domain.dto.Role;
import com.t1.authservice.domain.model.Token;
import com.t1.authservice.domain.model.User;
import com.t1.authservice.exception.InvalidRefreshTokenException;
import com.t1.authservice.exception.MissingAuthorizationHeaderException;
import com.t1.authservice.exception.SuchUserExistsException;
import com.t1.authservice.repository.TokenRepository;
import com.t1.authservice.repository.UserRepository;
import com.t1.authservice.service.contract.AuthenticationService;
import com.t1.authservice.service.contract.JweService;
import com.t1.authservice.service.contract.TokenAllowlistService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final JweService jweService;
    private final TokenAllowlistService tokenAllowlistService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    public AuthenticationResponse register(RegistrationRequest registrationRequest, HttpServletResponse response) {
        if (userRepository.existsByEmail(registrationRequest.getEmail())) {
            throw new SuchUserExistsException("User with this email already exists");
        }

        User user = User.builder()
                .login(registrationRequest.getLogin())
                .email(registrationRequest.getEmail())
                .password(passwordEncoder.encode(registrationRequest.getPassword()))
                .role(Role.ROLE_PREMIUM_USER)
                .build();

        userRepository.save(user);

        return generateAndSaveTokens(user, response);
    }

    @Override
    public AuthenticationResponse authenticate(LoginRequest loginRequest, HttpServletResponse response) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return generateAndSaveTokens(user, response);
    }

    @Override
    public AuthenticationResponse refreshToken(HttpServletRequest request, HttpServletResponse response) throws ParseException {
        String refreshToken = request.getHeader("X-Refresh-Token");
        if (refreshToken == null) {
            throw new MissingAuthorizationHeaderException("Refresh token missing");
        }

        String email = jweService.extractEmail(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!jweService.isTokenValid(refreshToken, user)) {
            throw new InvalidRefreshTokenException("Invalid refresh token");
        }

        return generateAndSaveTokens(user, response);
    }

    private AuthenticationResponse generateAndSaveTokens(User user, HttpServletResponse response) {
        revokeAllUserTokens(user);

        String accessToken = jweService.generateAccessToken(user);
        String refreshToken = jweService.generateRefreshToken(user);

        tokenAllowlistService.addToAllowlist(jweService.extractJti(accessToken));
        tokenAllowlistService.addToAllowlist(jweService.extractJti(refreshToken));

        saveUserToken(accessToken, refreshToken, user);

        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        response.setHeader("X-Refresh-Token", refreshToken);
        response.setHeader("Access-Control-Expose-Headers", "Authorization, X-Refresh-Token");

        return new AuthenticationResponse(accessToken, refreshToken);
    }

    @Override
    public void revokeAllToken(User user) {
        List<Token> validTokens = tokenRepository.findAllTokenByUser(user.getId());
        validTokens.forEach(token -> {
            token.setLoggedOut(true);
            tokenAllowlistService.removeFromAllowlist(jweService.extractJti(token.getAccessToken()));
            tokenAllowlistService.removeFromAllowlist(jweService.extractJti(token.getRefreshToken()));
        });
        tokenRepository.saveAll(validTokens);
    }

    @Override
    public void revokeAllTokenController(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        revokeAllToken(user);
    }

    public void saveUserToken(String accessToken, String refreshToken, User user) {
        Token token = Token.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .loggedOut(false)
                .user(user)
                .build();
        tokenRepository.save(token);
    }
}