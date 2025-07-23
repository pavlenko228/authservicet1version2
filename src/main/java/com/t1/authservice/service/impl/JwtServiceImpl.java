package com.t1.authservice.service.impl;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.t1.authservice.domain.model.User;
import com.t1.authservice.repository.TokenRepository;
import com.t1.authservice.service.contract.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    @Value("${security.jwt.secret_key}")
    public String secretKey;

    @Value("${security.jwt.access_token_expiration}")
    private long accessTokenExpiration;

    @Value("${security.jwt.refresh_token_expiration}")
    private long refreshTokenExpiration;

    private final TokenRepository tokenRepository;

    @Override
    public String generateAccessToken(User user) {
        return generateToken(user, accessTokenExpiration);
    }

    @Override
    public String generateRefreshToken(User user) {
        return generateToken(user, refreshTokenExpiration);
    }

    @Override
    public String generateToken(User user, long expiryTime) {
        long currentTime = System.currentTimeMillis();

        return Jwts.builder()
            .subject(user.getLogin())
            .claim("id", user.getId())
            .claim("email", user.getEmail())
            .claim("role", user.getRole())
            .issuedAt(new Date(currentTime))
            .expiration(new Date(currentTime + expiryTime))
            .signWith(getSigningKey())
            .compact();
    }

    @Override
    public boolean isAccessTokenValid(String token, User user) {
        boolean isAccessTokenValid = tokenRepository.findByAccessToken(token)
                .map(t -> !t.isLoggedOut()).orElse(false);

        return extractEmail(token).equals(user.getEmail())
                && !isTokenExpired(token)
                && isAccessTokenValid;
    }

    @Override
    public boolean isRefreshTokenValid(String token, User user) {
        boolean isRefreshTokenValid = tokenRepository.findByRefreshToken(token)
                .map(t -> !t.isLoggedOut()).orElse(false);

        return extractEmail(token).equals(user.getEmail())
                && !isTokenExpired(token)
                && isRefreshTokenValid;
    }

    @Override
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    
    @Override
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    @Override
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(extractAllClaims(token));
    }

    @Override
    public String extractUsername(String token) { 
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String extractEmail(String token) { 
        return extractClaim(token, claims -> claims.get("email", String.class));
    }
    
    @Override
    public Long extractId(String token) {
        return extractClaim(token, claims -> claims.get("id", Long.class));
    }

    @Override
    public String extractRole(String token) {
        return extractClaim(token, claims -> claims.get("role", String.class));
    }

    @Override
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    @Override
    public SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);

        return Keys.hmacShaKeyFor(keyBytes);
    }

}
