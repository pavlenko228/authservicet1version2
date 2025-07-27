package com.t1.authservice.jwt;

import java.text.ParseException;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;

public class JwtClaims {
    private final JWTClaimsSet claimsSet;

    public JwtClaims(JWTClaimsSet claimsSet) {
        this.claimsSet = claimsSet;
    }

    public String getSubject() {
        return claimsSet.getSubject();
    }

    public String getEmail() throws ParseException {
        return claimsSet.getStringClaim("email");
    }

    public Long getId() throws ParseException {
        return claimsSet.getLongClaim("id");
    }

    public String getRole() throws ParseException  {
        return claimsSet.getStringClaim("role");
    }

    public Date getExpirationTime() {
        return claimsSet.getExpirationTime();
    }

    public String getJwtId() {
        return claimsSet.getJWTID();
    }

    public Object getClaim(String string) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getClaim'");
    }
}
