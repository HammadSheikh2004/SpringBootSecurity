package com.mhis.springbootsecurity.DTOs;

import jakarta.persistence.Column;
import lombok.*;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginDTO {
    private String email;
    private String password;
}
