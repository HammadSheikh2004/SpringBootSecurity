package com.mhis.springbootsecurity.DTOs;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthResponse {

    private String userName;
    private String token;
    private String refreshToken;
}