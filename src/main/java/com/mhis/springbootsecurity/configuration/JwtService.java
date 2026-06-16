package com.mhis.springbootsecurity.configuration;

import com.mhis.springbootsecurity.entity.Roles;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    private String Secret;

    public JwtService(
            @Value("${JWT_SECRET_KEY}") String secret) {
        this.Secret = secret;
    }

    private Key getSignKey(){
        return Keys.hmacShaKeyFor(Secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String email, Roles role, UUID registrationId){
        return Jwts.builder().subject(email)
                .claim("Role", role)
                .claim("RegistrationId", registrationId)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 5))
                .signWith(getSignKey())
                .compact();
    }

    public String generateRefreshToken(String email, Roles role,
                                  UUID registrationId){
        return Jwts.builder().subject(email)
                .claim("Role", role)
                .claim("RegistrationId", registrationId)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 7))
                .signWith(getSignKey())
                .compact();
    }

    public String extractUserName(String token){
        return Jwts.parser()
                .verifyWith((SecretKey) getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
