package com.t1.authservice.service.contract;

public interface TokenAllowlistService {
    void addToAllowlist(String jti);
    void removeFromAllowlist(String jti);
    boolean isInAllowlist(String jti);
}