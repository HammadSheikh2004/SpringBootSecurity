package com.mhis.springbootsecurity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "registration")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Registration {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "registration_id")
    private UUID registrationId;

    @Column(name = "user_name", nullable = false)
    @NotNull(message = "User name Required!")
    private String userName;

    @Column(name = "email", nullable = false)
    @NotNull(message = "Email is not null!")
    @Email(message = "Email pattern is not valid!")
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Roles role = Roles.USER;

    @Column(name = "password", nullable = false)
    @NotNull(message = "Password is not null!")
    private String password;

    @Column(name = "confirm_password", nullable = false)
    @NotNull(message = "Confirm_password is not null!")
    private String confirmPassword;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();
}










