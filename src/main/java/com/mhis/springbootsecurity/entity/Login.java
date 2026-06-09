package com.mhis.springbootsecurity.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Login {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "login_id")
    private UUID login_id;

    @Column(name = "email", nullable = false)
    @NotNull(message = "Email is not null!")
    @Email(message = "Email pattern is not valid!")
    private String email;

    @Column(name = "password", nullable = false)
    @NotNull(message = "Password is not null!")
    private String password;
}
