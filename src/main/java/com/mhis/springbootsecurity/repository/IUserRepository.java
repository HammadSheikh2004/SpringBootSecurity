package com.mhis.springbootsecurity.repository;

import com.mhis.springbootsecurity.entity.Registration;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface IUserRepository extends JpaRepository<Registration, UUID> {
    boolean existsByEmail(String email);
    boolean existsByUserName(String userName);
    Registration findByEmail(String email);
}
