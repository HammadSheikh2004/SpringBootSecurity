package com.mhis.springbootsecurity.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "token")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "token_id")
    private UUID token_id;

    @Column(name = "user_name")
    private String userName = null;

    @Column(name = "user_id")
    private UUID userId = null;

    @Column(name = "expiry_date")
    private LocalDateTime expiryDate = null;

    @Column(name = "revoke")
    private boolean revoke;

    @Column(name = "refresh_token", length = 2000)
    private String refreshToken;
}
