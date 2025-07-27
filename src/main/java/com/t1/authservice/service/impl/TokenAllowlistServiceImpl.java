package com.t1.authservice.service.impl;

import com.t1.authservice.domain.model.AllowedToken;
import com.t1.authservice.repository.AllowedTokenRepository;
import com.t1.authservice.service.contract.TokenAllowlistService;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
@RequiredArgsConstructor
public class TokenAllowlistServiceImpl implements TokenAllowlistService {

    private final AllowedTokenRepository allowedTokenRepository;
    private final ConcurrentMap<String, Boolean> inMemoryAllowlist = new ConcurrentHashMap<>();

    @Override
    @Transactional
    public void addToAllowlist(String jti) {
        if (!inMemoryAllowlist.containsKey(jti)) {
            allowedTokenRepository.save(new AllowedToken(jti, Instant.now().plusSeconds(3600))); // TTL 1 час
            inMemoryAllowlist.put(jti, true);
        }
    }

    @Override
    @Transactional
    public void removeFromAllowlist(String jti) {
        allowedTokenRepository.deleteById(jti);
        inMemoryAllowlist.remove(jti);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isInAllowlist(String jti) {
        // Сначала проверяем в памяти
        if (inMemoryAllowlist.containsKey(jti)) {
            return true;
        }
        
        // Если нет в памяти, проверяем в БД
        boolean existsInDb = allowedTokenRepository.existsById(jti);
        if (existsInDb) {
            inMemoryAllowlist.put(jti, true); // Кэшируем
        }
        return existsInDb;
    }

    @Scheduled(fixedRate = 3600000) // Каждый час
    @Transactional
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        List<AllowedToken> expiredTokens = allowedTokenRepository.findByExpiryDateBefore(now);
        
        expiredTokens.forEach(token -> {
            allowedTokenRepository.delete(token);
            inMemoryAllowlist.remove(token.getJti());
        });
    }
}