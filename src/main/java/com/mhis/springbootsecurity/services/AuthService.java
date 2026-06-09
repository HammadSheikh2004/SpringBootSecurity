package com.mhis.springbootsecurity.services;

import com.mhis.springbootsecurity.DTOs.AuthResponse;
import com.mhis.springbootsecurity.DTOs.LoginDTO;
import com.mhis.springbootsecurity.DTOs.UserDTO;
import com.mhis.springbootsecurity.configuration.JwtService;
import com.mhis.springbootsecurity.entity.Registration;
import com.mhis.springbootsecurity.entity.Roles;
import com.mhis.springbootsecurity.entity.Token;
import com.mhis.springbootsecurity.repository.ITokenRepository;
import com.mhis.springbootsecurity.repository.IUserRepository;
import com.mhis.springbootsecurity.validation.PasswordValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;


@Service
public class AuthService {

    @Autowired
    private IUserRepository userRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private ITokenRepository tokenRepository;


    public UserDTO userRegistered(UserDTO userDTO) {

        if(userRepo.existsByEmail(userDTO.getEmail())){
            throw  new RuntimeException("Email already Exists");
        }

        if(userRepo.existsByUserName(userDTO.getUserName())){
            throw new RuntimeException("Username already Exists!");
        }

        List<String> errors = PasswordValidator.validate(userDTO.getPassword());

        if (!errors.isEmpty()) {
            throw new RuntimeException(String.join(", ", errors));
        }

        if (!userDTO.getPassword().equals(userDTO.getConfirmPassword())) {
            throw new IllegalArgumentException("Password and Confirm Password do not match");
        }

        String encryptedPassword =
                passwordEncoder.encode(userDTO.getPassword());

        String encryptedConfirmPassword =
                passwordEncoder.encode(userDTO.getConfirmPassword());

        Registration registration = Registration.builder()
                .userName(userDTO.getUserName())
                .email(userDTO.getEmail())
                .password(encryptedPassword)
                .confirmPassword(encryptedConfirmPassword)
                .role(Roles.USER)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now()).build();

        Registration savedUsers = userRepo.save(registration);

        return UserDTO.builder()
                .registrationId(savedUsers.getRegistrationId())
                .userName(savedUsers.getUserName())
                .email(savedUsers.getEmail())
                .role(savedUsers.getRole())
                .password(savedUsers.getPassword())
                .confirmPassword(savedUsers.getConfirmPassword())
                .createdAt(savedUsers.getCreatedAt())
                .updatedAt(savedUsers.getUpdatedAt()).build();
    }

    public AuthResponse signin(LoginDTO loginDTO) {

        Registration user =
                userRepo.findByEmail(loginDTO.getEmail());

        if(user == null){
            throw new RuntimeException("User not found");
        }

        if(!passwordEncoder.matches(
                loginDTO.getPassword(),
                user.getPassword())) {

            throw new RuntimeException("Invalid Password");
        }

        String accessToken =
                jwtService.generateToken(
                        user.getEmail(),
                        user.getRole(),
                        user.getRegistrationId());

        String refreshToken =
                jwtService.generateRefreshToken(
                        user.getEmail(),
                        user.getRole(),
                        user.getRegistrationId());

        Token tokenEntity = new Token();

        tokenEntity.setUserName(user.getUserName());
        tokenEntity.setUserId(user.getRegistrationId());
        tokenEntity.setRefreshToken(refreshToken);
        tokenEntity.setExpiryDate(
                LocalDateTime.now().plusDays(7));
        tokenEntity.setRevoke(false);

        tokenRepository.save(tokenEntity);

        return AuthResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthResponse refreshToken(String refreshToken){

        Token tokenEntity =
                tokenRepository.findByRefreshToken(refreshToken)
                        .orElseThrow(() ->
                                new RuntimeException("Invalid refresh token"));

        if(tokenEntity.isRevoke()){
            throw new RuntimeException("Token revoked");
        }

        if(tokenEntity.getExpiryDate().isBefore(LocalDateTime.now())){
            throw new RuntimeException("Token expired");
        }

        Registration user =
                userRepo.findById(tokenEntity.getUserId())
                        .orElseThrow();

        String newAccessToken =
                jwtService.generateToken(
                        user.getEmail(),
                        user.getRole(),
                        user.getRegistrationId());

        return AuthResponse.builder()
                .token(newAccessToken)
                .userName(user.getUserName())
                .refreshToken(refreshToken)
                .build();
    }

    public void logout(String refreshToken) {

        Token tokenEntity =
                tokenRepository.findByRefreshToken(refreshToken)
                        .orElseThrow(() -> new RuntimeException("Invalid token"));

        tokenEntity.setRevoke(true);
        tokenRepository.save(tokenEntity);
    }


}

