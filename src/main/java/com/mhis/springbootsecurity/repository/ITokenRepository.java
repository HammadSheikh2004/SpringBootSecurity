package com.mhis.springbootsecurity.repository;

import com.mhis.springbootsecurity.entity.Login;
import com.mhis.springbootsecurity.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ITokenRepository extends JpaRepository<Token, UUID> {
    Optional<Token> findByRefreshToken(String refreshToken);
}
