package com.t1.authservice.service.contract;

import java.text.ParseException;
import java.util.Date;

import com.t1.authservice.domain.model.User;
import com.t1.authservice.jwt.JwtClaims;

public interface JweService {

    String generateAccessToken(User user);

    String generateRefreshToken(User user);

    String generateToken(User user, long expiryTime);

    boolean isTokenValid(String token, User user);

    boolean isTokenExpired(String token);

    JwtClaims validateToken(String token);

    String extractJti(String token);

    default String extractUsername(String token) {
        return validateToken(token).getSubject();
    }

    default String extractEmail(String token) throws ParseException {
        return validateToken(token).getEmail();
    }

    default Long extractId(String token) throws ParseException {
        return validateToken(token).getId();
    }

    default String extractRole(String token) throws ParseException {
        return validateToken(token).getRole();
    }

    default Date extractExpiration(String token) {
        return validateToken(token).getExpirationTime();
    }
}
