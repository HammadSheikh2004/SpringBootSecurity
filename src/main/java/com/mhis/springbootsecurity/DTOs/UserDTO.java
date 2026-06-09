package com.mhis.springbootsecurity.DTOs;

import com.mhis.springbootsecurity.entity.Roles;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDTO {

    @Column(name = "registration_id")
    private UUID registrationId;

    @NotNull(message = "User name Required!")
    private String userName;

    @NotNull(message = "Email is not null!")
    private String email;

    private Roles role = Roles.USER;

    @NotNull(message = "Password is not null!")
    private String password;

    @NotNull(message = "Confirm_password is not null!")
    private String confirmPassword;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();
}
