package com.t1.authservice.service.contract;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import com.t1.authservice.domain.model.User;

import io.jsonwebtoken.Claims;


public interface JwtService {

    String generateAccessToken(User user);

    String generateRefreshToken(User user);

    String generateToken(User user, long expiryTime);

    boolean isAccessTokenValid(String token, User user);

    boolean isRefreshTokenValid(String token, User user);

    boolean isTokenExpired(String token);

    Claims extractAllClaims(String token);

    <T> T extractClaim(String token, Function<Claims, T> resolver);

    String extractUsername(String token);

    String extractEmail(String token);

    Long extractId(String token);

    String extractRole(String token);

    Date extractExpiration(String token);

    SecretKey getSigningKey();

}
