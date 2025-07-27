package com.t1.authservice.service.impl;

import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.t1.authservice.domain.model.User;
import com.t1.authservice.jwt.JwtClaims;
import com.t1.authservice.repository.TokenRepository;
import com.t1.authservice.service.contract.JweService;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JweServiceImpl implements JweService {

    @Value("${security.jwe.secret_key}")
    private String secretKey;

    @Value("${security.jwe.access_token_expiration}")
    private long accessTokenExpiration;

    @Value("${security.jwe.refresh_token_expiration}")
    private long refreshTokenExpiration;

    private final TokenRepository tokenRepository;
    private final OctetSequenceKey jwk;

    @PostConstruct
    public void init() {
        this.jwk = new OctetSequenceKeyGenerator(256)
            .keyID("jwe-key")
            .generate();
    }

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
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(user.getLogin())
                .claim("id", user.getId())
                .claim("email", user.getEmail())
                .claim("role", user.getRole())
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + expiryTime))
                .jwtID(UUID.randomUUID().toString()) // Уникальный ID для allowlist
                .build();

            JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM).build(),
                new Payload(claims.toJSONObject())
            );
            jwe.encrypt(new DirectEncrypter(jwk.toOctetSequenceKey()));
            return jwe.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWE token", e);
        }
    }

    @Override
    public boolean isTokenValid(String token, User user) {
        try {
            JwtClaims claims = validateToken(token);
            boolean isTokenValid = tokenRepository.findByAccessToken(token)
                .map(t -> !t.isLoggedOut()).orElse(false);

            return claims.getClaim("email").equals(user.getEmail())
                && !isTokenExpired(token)
                && isTokenValid;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public JwtClaims validateToken(String token) {
        try {
            JWEObject jwe = JWEObject.parse(token);
            jwe.decrypt(new DirectDecrypter(jwk.toOctetSequenceKey()));
            return JwtClaimsSet.parse(jwe.getPayload().toJSONObject());
        } catch (Exception e) {
            throw new RuntimeException("Invalid JWE token", e);
        }
    }

    @Override
    public String extractUsername(String token) {
        return validateToken(token).getSubject();
    }

    @Override
    public String extractEmail(String token) {
        return validateToken(token).getStringClaim("email");
    }

    @Override
    public Long extractId(String token) {
        return validateToken(token).getLongClaim("id");
    }

    @Override
    public String extractRole(String token) {
        return validateToken(token).getStringClaim("role");
    }

    @Override
    public Date extractExpiration(String token) {
        return validateToken(token).getExpirationTime();
    }

    @Override
    public String extractJti(String token) {
        return validateToken(token).getJWTID();
    }
}